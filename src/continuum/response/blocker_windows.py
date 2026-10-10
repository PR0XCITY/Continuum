"""Device disable/enable via pnputil, with safety rails.

Responsibility: the only place in Continuum allowed to disable or
re-enable a physical HID device. This is the most safety-critical
module in the project; every rule below exists to stop Continuum from
locking the user out of their own machine, and is checked in pure,
dependency-free code before any real pnputil call is ever attempted.

Safety rails, enforced by evaluate_block_decision() before anything else:
    - never disable a device on the configured allowlist,
    - never disable a non-USB device unless explicitly configured to
      (a laptop's built-in keyboard is usually enumerated as PS2, not
      USB; it being internal is exactly why this project should not
      touch it by default),
    - never disable a device if doing so would leave zero other
      enabled keyboards attached.

Mechanism:
    - the actual enable/disable action goes through `pnputil`, as
      required; the exit code is never trusted on its own, every
      action is verified by re-querying the device's real status via
      CfgMgr32 (CM_Get_DevNode_Status),
    - a Digispark-style composite USB device exposes a child HID
      keyboard node; capture's instance_id is already that child node
      (Raw Input resolves at the HID collection level), so disabling
      is tried there first; if verification shows it is still started,
      the parent USB node is located via CfgMgr32 (CM_Get_Parent) and
      disabled instead,
    - disabling requires an elevated process; this is checked here too,
      independent of whatever decided the configured response mode,
    - every device this module disables is persisted to
      data/disabled_devices.json immediately, so a crash cannot strand
      a disabled device: the next run's DeviceBlocker() reloads that
      file and can still release everything in it.

All pnputil and CfgMgr32 calls are module-level functions that tests
monkeypatch; nothing here needs a real elevated session or real
hardware to test the decision logic.
"""

from __future__ import annotations

import ctypes
import json
import subprocess
import sys
from collections.abc import Collection, Sequence
from ctypes import wintypes
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path

from continuum.common.logging import get_logger

IS_WINDOWS = sys.platform == "win32"

_REPO_ROOT = Path(__file__).resolve().parents[3]
DEFAULT_DISABLED_DEVICES_PATH = _REPO_ROOT / "data" / "disabled_devices.json"
DEFAULT_AUTO_RELEASE_TIMEOUT_SECONDS = 600.0

PNPUTIL_TIMEOUT_SECONDS = 15.0

CM_LOCATE_DEVNODE_NORMAL = 0x00000000
CR_SUCCESS = 0x00000000
MAX_DEVICE_ID_LEN = 200
DN_STARTED = 0x00000008

_logger = get_logger("response.blocker_windows")

if IS_WINDOWS:
    _cfgmgr32 = ctypes.WinDLL("cfgmgr32", use_last_error=True)
    _shell32 = ctypes.WinDLL("shell32", use_last_error=True)

    _cfgmgr32.CM_Locate_DevNodeW.argtypes = [
        ctypes.POINTER(wintypes.ULONG),
        wintypes.LPCWSTR,
        wintypes.ULONG,
    ]
    _cfgmgr32.CM_Locate_DevNodeW.restype = wintypes.ULONG

    _cfgmgr32.CM_Get_Parent.argtypes = [
        ctypes.POINTER(wintypes.ULONG),
        wintypes.ULONG,
        wintypes.ULONG,
    ]
    _cfgmgr32.CM_Get_Parent.restype = wintypes.ULONG

    _cfgmgr32.CM_Get_Device_IDW.argtypes = [
        wintypes.ULONG,
        wintypes.LPWSTR,
        wintypes.ULONG,
        wintypes.ULONG,
    ]
    _cfgmgr32.CM_Get_Device_IDW.restype = wintypes.ULONG

    _cfgmgr32.CM_Get_DevNode_Status.argtypes = [
        ctypes.POINTER(wintypes.ULONG),
        ctypes.POINTER(wintypes.ULONG),
        wintypes.ULONG,
        wintypes.ULONG,
    ]
    _cfgmgr32.CM_Get_DevNode_Status.restype = wintypes.ULONG

    _shell32.IsUserAnAdmin.argtypes = []
    _shell32.IsUserAnAdmin.restype = wintypes.BOOL
else:
    _cfgmgr32 = None
    _shell32 = None


# --- elevation and device-tree lookups (CfgMgr32), mockable ----------------


def is_elevated() -> bool:
    """True if this process is running as Administrator. False off Windows."""
    if not IS_WINDOWS or _shell32 is None:
        return False
    try:
        return bool(_shell32.IsUserAnAdmin())
    except OSError:
        return False


def _locate_devnode(instance_id: str) -> int | None:
    if not IS_WINDOWS or _cfgmgr32 is None:
        return None
    devinst = wintypes.ULONG(0)
    result = _cfgmgr32.CM_Locate_DevNodeW(
        ctypes.byref(devinst), instance_id, CM_LOCATE_DEVNODE_NORMAL
    )
    if result != CR_SUCCESS:
        return None
    return devinst.value


def get_parent_instance_id(instance_id: str) -> str | None:
    """The parent device's instance id, via the real Windows device tree.

    Used to fall back from a composite USB device's HID keyboard child
    node to its parent when disabling the child alone was not enough.
    Returns None if the device, or its parent, cannot be found.
    """
    devinst = _locate_devnode(instance_id)
    if devinst is None:
        return None

    parent_devinst = wintypes.ULONG(0)
    result = _cfgmgr32.CM_Get_Parent(ctypes.byref(parent_devinst), devinst, 0)
    if result != CR_SUCCESS:
        return None

    buffer = ctypes.create_unicode_buffer(MAX_DEVICE_ID_LEN)
    result = _cfgmgr32.CM_Get_Device_IDW(parent_devinst.value, buffer, MAX_DEVICE_ID_LEN, 0)
    if result != CR_SUCCESS:
        return None
    return buffer.value


def is_devnode_started(instance_id: str) -> bool | None:
    """True if enabled, False if disabled, None if the device cannot be found.

    This is the verification step: pnputil's exit code is never trusted
    alone, every disable or enable is confirmed by asking Windows for
    the device's real status afterward.
    """
    devinst = _locate_devnode(instance_id)
    if devinst is None:
        return None

    status = wintypes.ULONG(0)
    problem = wintypes.ULONG(0)
    result = _cfgmgr32.CM_Get_DevNode_Status(
        ctypes.byref(status), ctypes.byref(problem), devinst, 0
    )
    if result != CR_SUCCESS:
        return None
    return bool(status.value & DN_STARTED)


# --- pnputil, mockable -------------------------------------------------------


def _run_pnputil(args: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["pnputil.exe", *args],
        capture_output=True,
        text=True,
        timeout=PNPUTIL_TIMEOUT_SECONDS,
        check=False,
    )


def _pnputil_disable(instance_id: str) -> subprocess.CompletedProcess[str]:
    return _run_pnputil(["/disable-device", instance_id])


def _pnputil_enable(instance_id: str) -> subprocess.CompletedProcess[str]:
    return _run_pnputil(["/enable-device", instance_id])


# --- pure safety-rail decision, no Windows calls at all ----------------------


@dataclass(frozen=True)
class BlockDecision:
    allowed: bool
    reason: str


def evaluate_block_decision(
    instance_id: str,
    *,
    is_usb: bool,
    allowlist: Collection[str],
    other_enabled_keyboard_count: int,
    allow_non_usb: bool = False,
) -> BlockDecision:
    """Decide whether instance_id may be disabled at all.

    Called before any pnputil call is ever attempted. other_enabled_
    keyboard_count is the number of OTHER enabled keyboard-class
    devices, not counting instance_id itself; disabling is refused if
    that would reach zero.
    """
    if instance_id in allowlist:
        return BlockDecision(False, "device is on the allowlist")
    if not is_usb and not allow_non_usb:
        return BlockDecision(False, "non-USB device; disabling it is not enabled")
    if other_enabled_keyboard_count < 1:
        return BlockDecision(False, "would disable the last remaining keyboard")
    return BlockDecision(True, "safety checks passed")


# --- persisted disabled-device records ---------------------------------------


@dataclass
class DisabledDeviceRecord:
    """One device this module has disabled and is responsible for releasing."""

    requested_instance_id: str
    disabled_instance_id: str
    reason: str
    disabled_at: datetime
    auto_release_at: datetime

    def to_json(self) -> dict[str, str]:
        return {
            "requested_instance_id": self.requested_instance_id,
            "disabled_instance_id": self.disabled_instance_id,
            "reason": self.reason,
            "disabled_at": self.disabled_at.astimezone(UTC).isoformat(),
            "auto_release_at": self.auto_release_at.astimezone(UTC).isoformat(),
        }

    @classmethod
    def from_json(cls, data: dict[str, str]) -> DisabledDeviceRecord:
        return cls(
            requested_instance_id=data["requested_instance_id"],
            disabled_instance_id=data["disabled_instance_id"],
            reason=data["reason"],
            disabled_at=datetime.fromisoformat(data["disabled_at"]),
            auto_release_at=datetime.fromisoformat(data["auto_release_at"]),
        )


def load_disabled_devices(path: Path) -> list[DisabledDeviceRecord]:
    if not path.exists():
        return []
    raw = json.loads(path.read_text(encoding="utf-8"))
    return [DisabledDeviceRecord.from_json(item) for item in raw]


def save_disabled_devices(path: Path, records: Sequence[DisabledDeviceRecord]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps([record.to_json() for record in records], indent=2),
        encoding="utf-8",
    )


# --- the orchestrator ---------------------------------------------------------


@dataclass(frozen=True)
class BlockResult:
    success: bool
    reason: str
    disabled_instance_id: str | None
    dry_run: bool = False


class DeviceBlocker:
    """Owns every disable/enable decision and the disabled-device list.

    Loads data/disabled_devices.json on construction, so a fresh
    DeviceBlocker after a crash already knows what was left disabled
    and can release it. Every successful disable is persisted to that
    file immediately, before this function returns.
    """

    def __init__(
        self,
        *,
        dry_run: bool = False,
        allow_non_usb: bool = False,
        auto_release_timeout_seconds: float = DEFAULT_AUTO_RELEASE_TIMEOUT_SECONDS,
        disabled_devices_path: Path = DEFAULT_DISABLED_DEVICES_PATH,
    ) -> None:
        self._dry_run = dry_run
        self._allow_non_usb = allow_non_usb
        self._auto_release_timeout_seconds = auto_release_timeout_seconds
        self._path = disabled_devices_path
        self._records: dict[str, DisabledDeviceRecord] = {
            record.requested_instance_id: record for record in load_disabled_devices(self._path)
        }

    @property
    def disabled_instance_ids(self) -> list[str]:
        """The real device nodes currently disabled (child or parent)."""
        return [record.disabled_instance_id for record in self._records.values()]

    def is_disabled(self, requested_instance_id: str) -> bool:
        return requested_instance_id in self._records

    def disable(
        self,
        instance_id: str,
        *,
        is_usb: bool,
        allowlist: Collection[str],
        other_enabled_keyboard_count: int,
        reason: str = "detected injection attack",
    ) -> BlockResult:
        if instance_id in self._records:
            existing = self._records[instance_id]
            return BlockResult(
                success=True,
                reason="already disabled",
                disabled_instance_id=existing.disabled_instance_id,
                dry_run=self._dry_run,
            )

        decision = evaluate_block_decision(
            instance_id,
            is_usb=is_usb,
            allowlist=allowlist,
            other_enabled_keyboard_count=other_enabled_keyboard_count,
            allow_non_usb=self._allow_non_usb,
        )
        if not decision.allowed:
            _logger.warning("refused to disable %s: %s", instance_id, decision.reason)
            return BlockResult(
                success=False,
                reason=decision.reason,
                disabled_instance_id=None,
                dry_run=self._dry_run,
            )

        if self._dry_run:
            _logger.info("dry_run: would disable %s (%s)", instance_id, reason)
            return BlockResult(
                success=True, reason="dry_run", disabled_instance_id=instance_id, dry_run=True
            )

        if not is_elevated():
            _logger.warning("refused to disable %s: process is not elevated", instance_id)
            return BlockResult(
                success=False, reason="not elevated", disabled_instance_id=None, dry_run=False
            )

        disabled_id = self._disable_with_fallback(instance_id)
        if disabled_id is None:
            _logger.error("failed to disable %s (tried the device and its parent)", instance_id)
            return BlockResult(
                success=False,
                reason="pnputil disable failed",
                disabled_instance_id=None,
                dry_run=False,
            )

        now = datetime.now(UTC)
        record = DisabledDeviceRecord(
            requested_instance_id=instance_id,
            disabled_instance_id=disabled_id,
            reason=reason,
            disabled_at=now,
            auto_release_at=now + timedelta(seconds=self._auto_release_timeout_seconds),
        )
        self._records[instance_id] = record
        self._persist()
        _logger.info(
            "disabled %s (node actually disabled: %s): %s", instance_id, disabled_id, reason
        )
        return BlockResult(
            success=True, reason=reason, disabled_instance_id=disabled_id, dry_run=False
        )

    def _disable_with_fallback(self, instance_id: str) -> str | None:
        if self._try_disable(instance_id):
            return instance_id
        parent_id = get_parent_instance_id(instance_id)
        if parent_id and self._try_disable(parent_id):
            return parent_id
        return None

    def _try_disable(self, instance_id: str) -> bool:
        _pnputil_disable(instance_id)
        # The exit code is not trusted; re-query the real device status.
        return is_devnode_started(instance_id) is False

    def enable(self, requested_instance_id: str) -> bool:
        record = self._records.get(requested_instance_id)
        if record is None:
            return False

        if self._dry_run:
            _logger.info("dry_run: would enable %s", record.disabled_instance_id)
            del self._records[requested_instance_id]
            self._persist()
            return True

        success = self._try_enable(record.disabled_instance_id)
        if success:
            del self._records[requested_instance_id]
            self._persist()
            _logger.info("enabled %s", record.disabled_instance_id)
        else:
            _logger.error("failed to enable %s", record.disabled_instance_id)
        return success

    def _try_enable(self, instance_id: str) -> bool:
        _pnputil_enable(instance_id)
        status = is_devnode_started(instance_id)
        # If the device can no longer be found at all (unplugged while
        # disabled), there is nothing left to re-enable; treat that as
        # released rather than as a stuck failure.
        return status is True or status is None

    def release_all(self) -> list[str]:
        """Re-enable every tracked device, regardless of its own timer."""
        released = []
        for requested_id in list(self._records):
            if self.enable(requested_id):
                released.append(requested_id)
        return released

    def forget_released_elsewhere(self) -> list[str]:
        """Drop records another process has already released, such as --release-all.

        A record is dropped only when it is missing from the file on disk
        AND its device is confirmed enabled again (or no longer present).
        If the file merely lost an entry while the device is still
        disabled, the record is kept, so the auto-release safety net
        always still covers it.
        """
        on_disk = {record.requested_instance_id for record in load_disabled_devices(self._path)}
        forgotten = []
        for requested_id, record in list(self._records.items()):
            if requested_id in on_disk:
                continue
            if is_devnode_started(record.disabled_instance_id) is not False:
                del self._records[requested_id]
                forgotten.append(requested_id)
        if forgotten:
            _logger.info("released by another process: %s", ", ".join(forgotten))
        return forgotten

    def check_auto_release(self, *, now: datetime | None = None) -> list[str]:
        """Re-enable any device whose auto-release timeout has passed."""
        current = now if now is not None else datetime.now(UTC)
        expired = [
            requested_id
            for requested_id, record in self._records.items()
            if record.auto_release_at <= current
        ]
        released = []
        for requested_id in expired:
            if self.enable(requested_id):
                released.append(requested_id)
        return released

    def _persist(self) -> None:
        save_disabled_devices(self._path, list(self._records.values()))

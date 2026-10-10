"""Operator-visible alerting.

Responsibility: raise a local toast notification (via winotify), print a
terminal message, and append an entry to a local events log, so an
operator sitting at the machine sees what happened without needing to
read logs. Every call here only ever receives event_type, a short
message, an optional device_id and a details mapping the caller
controls; nothing upstream of this module ever has access to which key
was pressed, so there is nothing here that could leak it.
"""

from __future__ import annotations

import json
import sys
from datetime import UTC, datetime
from pathlib import Path

IS_WINDOWS = sys.platform == "win32"

_REPO_ROOT = Path(__file__).resolve().parents[3]
DEFAULT_EVENTS_LOG_PATH = _REPO_ROOT / "data" / "logs" / "events.jsonl"

APP_ID = "Continuum"


def log_event(
    event_type: str,
    message: str,
    *,
    device_id: str | None = None,
    details: dict[str, object] | None = None,
    path: Path = DEFAULT_EVENTS_LOG_PATH,
) -> None:
    """Append one line to the local events log."""
    entry = {
        "timestamp": datetime.now(UTC).isoformat(),
        "event_type": event_type,
        "device_id": device_id,
        "message": message,
        "details": details or {},
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(entry) + "\n")


def _send_toast(title: str, message: str) -> bool:
    """Best-effort Windows toast via winotify. Never raises."""
    if not IS_WINDOWS:
        return False
    try:
        from winotify import Notification

        toast = Notification(app_id=APP_ID, title=title, msg=message)
        toast.show()
        return True
    except Exception:  # noqa: BLE001 - a failed toast must never break response
        return False


def notify(
    title: str,
    message: str,
    *,
    device_id: str | None = None,
    event_type: str = "notification",
    details: dict[str, object] | None = None,
    log_path: Path = DEFAULT_EVENTS_LOG_PATH,
) -> None:
    """Tell the operator what happened: terminal, toast, and the events log."""
    print(f"[Continuum] {title}: {message}")
    _send_toast(title, message)
    log_event(event_type, message, device_id=device_id, details=details, path=log_path)

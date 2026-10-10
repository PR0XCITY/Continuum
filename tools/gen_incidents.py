"""Generate seeded synthetic incidents and load them through the connector API.

Usage (with the connector running, see `just run-api`):
    python tools/gen_incidents.py                 # 200 incidents, seed 1337
    python tools/gen_incidents.py --count 300 --seed 7
    python tools/gen_incidents.py --dry-run       # generate and summarise only

Builds IncidentRecords spread over the last --days days and POSTs each
one to /incidents with the bearer token from the environment variable
named by connector.auth_token_env_var. Going through the API on
purpose exercises the whole ingest path: schema validation, notes
sanitising, SQLite persistence, the fixed-template RAG document, the
ingest queue, and finally the connector's background RAG watcher.

Reproducible: incident ids come from uuid5(seed, index) and every
random choice from random.Random(seed), so the same seed always gives
the same incidents. Timestamps are offsets back from --anchor
(default: today at 00:00 UTC), so re-running on the same day posts
identical records, and re-running on a later day posts nothing new
because the connector deduplicates on incident_id.

Every device below is fictional test data; vendor and product ids are
illustrative. A handful of NOTABLE_INCIDENTS have distinctive notes so
data/eval/rag_questions.yaml can ask about specific incident history.
"""

from __future__ import annotations

import argparse
import os
import random
import sys
import time
import uuid
from collections import Counter
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

import httpx

from continuum.common.config import get_settings
from continuum.common.schemas import IncidentRecord

DEFAULT_SEED = 1337
DEFAULT_COUNT = 200
DEFAULT_DAYS = 90
THRESHOLD = 0.65

INCIDENT_ID_NAMESPACE = uuid.UUID("6b1c4f9e-2d0a-4c8e-9f57-3a1e0c2b7d44")

RATE_LIMIT_RETRY_SECONDS = 5.0
RATE_LIMIT_MAX_RETRIES = 30

MITRE_DEFAULT = "T1200 Hardware Additions"


@dataclass(frozen=True)
class DeviceProfile:
    key: str
    name: str
    vendor_id: str
    product_id: str
    legitimate: bool


ATTACK_DEVICES = (
    DeviceProfile("digispark", "Digispark ATtiny85 HID", "16D0", "0753", False),
    DeviceProfile("leonardo", "Arduino Leonardo Keyboard", "2341", "8036", False),
    DeviceProfile("teensy", "Teensyduino Keyboard", "16C0", "0482", False),
    DeviceProfile("pico", "RP2040 Composite HID", "2E8A", "000A", False),
    DeviceProfile("spoofed", "HID Keyboard Device", "046D", "C31C", False),
    DeviceProfile("cable", "USB Composite Device", "05AC", "024F", False),
)

LEGITIMATE_DEVICES = (
    DeviceProfile("streamdeck", "Elgato Stream Deck", "0FD9", "0060", True),
    DeviceProfile("scanner", "Honeywell Barcode Scanner", "0C2E", "0B61", True),
    DeviceProfile("macropad", "Programmable Macro Pad", "1209", "A8F8", True),
    DeviceProfile("gaming", "Razer Gaming Keyboard", "1532", "0228", True),
    DeviceProfile("logitech", "Logitech USB Keyboard", "046D", "C31C", True),
    DeviceProfile("remote", "Wireless Presenter Remote", "046D", "C538", True),
)

ALL_DEVICES = {d.key: d for d in ATTACK_DEVICES + LEGITIMATE_DEVICES}

ATTACK_PATTERN_WEIGHTS = {
    "burst_injection": 45,
    "slowed_injection": 25,
    "randomized_injection": 20,
    "unknown": 10,
}

SCORE_RANGES = {
    "burst_injection": (1.6, 3.6),
    "slowed_injection": (0.8, 1.7),
    "randomized_injection": (0.9, 2.1),
    "unknown": (0.7, 1.4),
}

TIME_TO_DETECT_RANGES_MS = {
    "burst_injection": (110, 600),
    "slowed_injection": (700, 2600),
    "randomized_injection": (450, 1900),
    "unknown": (300, 1500),
}

ROUTINE_ATTACK_NOTES = (
    "",
    "",
    "",
    "Device removed and bagged. No commands found in PowerShell history.",
    "User did not recognise the device. Credentials rotated as a precaution.",
    "Short exposure window; Run dialog history showed no new entries.",
    "Device found in a rear port behind the monitor stand.",
    "Security team notified; forensic image taken before reuse.",
)

ROUTINE_FALSE_POSITIVE_NOTES = {
    "streamdeck": "False positive: macro button on a Stream Deck replayed a saved text snippet.",
    "scanner": "False positive: barcode scanner in keyboard emulation mode during stock intake.",
    "macropad": "False positive: programmable macro pad used for a repetitive data entry task.",
    "gaming": "False positive: on-board macro of a gaming keyboard triggered during a game.",
    "logitech": "False positive: fast typist on a standard keyboard, score near threshold.",
    "remote": "False positive: presenter remote sending repeated page-down keystrokes.",
}

# Distinctive incidents with fixed content, placed at the start of the
# generated list so their ids are uuid5(seed, 0..n-1).
NOTABLE_INCIDENTS: tuple[dict, ...] = (
    dict(
        device="digispark",
        days_ago=12.4,
        attack_pattern="burst_injection",
        verdict="blocked",
        anomaly_score=3.12,
        action_taken="locked_and_disabled",
        time_to_detect_ms=340,
        mitre_technique="T1200 Hardware Additions; T1053.005 Scheduled Task",
        recommended_followups=[
            "rotate_credentials",
            "capture_forensic_image",
            "notify_security_team",
        ],
        notes=(
            "Finance office reception PC. Payload opened the Run dialog and started "
            "PowerShell; a scheduled task named UpdaterSvc was created before the lock. "
            "Task removed and credentials rotated."
        ),
    ),
    dict(
        device="streamdeck",
        days_ago=33.1,
        attack_pattern="unknown",
        verdict="blocked",
        anomaly_score=0.74,
        action_taken="locked_and_disabled",
        time_to_detect_ms=520,
        recommended_followups=["update_device_allowlist", "no_action_required"],
        notes=(
            "False positive: Elgato Stream Deck macro pad on the video editing workstation "
            "replaying a saved text snippet. Device instance id added to the allowlist."
        ),
    ),
    dict(
        device="scanner",
        days_ago=47.8,
        attack_pattern="slowed_injection",
        verdict="blocked",
        anomaly_score=0.71,
        action_taken="device_disabled",
        time_to_detect_ms=880,
        recommended_followups=["update_device_allowlist"],
        notes=(
            "False positive: warehouse barcode scanner in keyboard emulation mode while "
            "scanning parcels at the loading dock. Allowlisted after review."
        ),
    ),
    dict(
        device="spoofed",
        days_ago=5.6,
        attack_pattern="slowed_injection",
        verdict="blocked",
        anomaly_score=1.38,
        action_taken="locked_and_disabled",
        time_to_detect_ms=1900,
        recommended_followups=[
            "review_physical_access_logs",
            "notify_security_team",
            "inspect_usb_ports",
        ],
        notes=(
            "USB stick delivered in an unsolicited parcel to the mailroom; a staff member "
            "plugged it in. It posed as a Logitech keyboard. Slowed injection stopped after "
            "1.9 s. No commands found in PowerShell history."
        ),
    ),
    dict(
        device="pico",
        days_ago=71.2,
        attack_pattern="randomized_injection",
        verdict="blocked",
        anomaly_score=1.21,
        action_taken="alert_only",
        time_to_detect_ms=4100,
        mitre_technique="T1200 Hardware Additions; T1059.003 Windows Command Shell",
        recommended_followups=["capture_forensic_image", "rotate_credentials"],
        notes=(
            "Pilot group running in alert_only mode, so the device was not blocked. "
            "Randomized injection typed for about 4 seconds and event 4688 shows cmd.exe "
            "launched. Workstation reimaged."
        ),
    ),
    dict(
        device="leonardo",
        days_ago=21.9,
        attack_pattern="burst_injection",
        verdict="blocked",
        anomaly_score=2.64,
        action_taken="locked_and_disabled",
        time_to_detect_ms=210,
        recommended_followups=["no_action_required"],
        notes=(
            "Electronics lab: Arduino Leonardo flashed with a test sketch during a hardware "
            "class. Confirmed as an authorised training exercise, no further action."
        ),
    ),
    dict(
        device="cable",
        days_ago=60.3,
        attack_pattern="burst_injection",
        verdict="blocked",
        anomaly_score=2.95,
        action_taken="locked_and_disabled",
        time_to_detect_ms=260,
        recommended_followups=[
            "review_physical_access_logs",
            "inspect_usb_ports",
            "isolate_device",
        ],
        notes=(
            "Charging cable with an embedded injection implant found on the library kiosk. "
            "Building access logs requested and camera footage reviewed."
        ),
    ),
    dict(
        device="logitech",
        days_ago=2.3,
        attack_pattern="unknown",
        verdict="suspicious",
        anomaly_score=0.68,
        action_taken="none",
        time_to_detect_ms=0,
        recommended_followups=["no_action_required"],
        notes=(
            "False positive: very fast typist transcribing meeting minutes on a standard "
            "keyboard. Score just above threshold; no allowlist change made."
        ),
    ),
)


def incident_id_for(seed: int, index: int) -> uuid.UUID:
    return uuid.uuid5(INCIDENT_ID_NAMESPACE, f"continuum-synthetic/{seed}/{index}")


def default_anchor() -> datetime:
    return datetime.now(UTC).replace(hour=0, minute=0, second=0, microsecond=0)


def _device_payload(profile: DeviceProfile, rng: random.Random, detected_at: datetime) -> dict:
    serial = f"{rng.getrandbits(24):06X}"
    instance_id = f"HID\\VID_{profile.vendor_id}&PID_{profile.product_id}\\7&{serial}&0&0000"
    return dict(
        device_id=instance_id,
        vendor_id=profile.vendor_id,
        product_id=profile.product_id,
        name=profile.name,
        bus_type="USB",
        is_usb=True,
        instance_id=instance_id,
        first_seen=(detected_at - timedelta(seconds=rng.uniform(1, 30))).isoformat(),
    )


def _features(pattern: str, rng: random.Random) -> dict[str, float]:
    if pattern == "burst_injection":
        flight_mean, flight_std = rng.uniform(4, 15), rng.uniform(0.2, 2.0)
    elif pattern == "slowed_injection":
        flight_mean, flight_std = rng.uniform(80, 160), rng.uniform(1, 6)
    elif pattern == "randomized_injection":
        flight_mean, flight_std = rng.uniform(60, 140), rng.uniform(20, 50)
    else:
        flight_mean, flight_std = rng.uniform(30, 120), rng.uniform(5, 30)
    return {
        "flight_mean_ms": round(flight_mean, 2),
        "flight_std_ms": round(flight_std, 2),
        "flight_cv": round(flight_std / flight_mean, 4),
        "dwell_mean_ms": round(rng.uniform(5, 90), 2),
        "burst_score": round(rng.uniform(0.0, 1.0), 3),
        "interval_entropy": round(rng.uniform(0.5, 4.0), 3),
    }


def _attack_followups(rng: random.Random, action: str) -> list[str]:
    followups = ["isolate_device", "inspect_usb_ports"]
    if rng.random() < 0.4:
        followups.append("rotate_credentials")
    if rng.random() < 0.3:
        followups.append("review_physical_access_logs")
    if rng.random() < 0.2 or action == "alert_only":
        followups.append("capture_forensic_image")
    if rng.random() < 0.5:
        followups.append("notify_security_team")
    return followups


def _routine_incident(rng: random.Random, detected_at: datetime) -> dict:
    roll = rng.random()
    if roll < 0.08:
        profile = rng.choice(LEGITIMATE_DEVICES)
        pattern = rng.choice(["slowed_injection", "unknown"])
        verdict = rng.choice(["blocked", "suspicious"])
        action = "locked_and_disabled" if verdict == "blocked" else "none"
        return dict(
            device=_device_payload(profile, rng, detected_at),
            anomaly_score=round(rng.uniform(THRESHOLD + 0.01, THRESHOLD + 0.25), 3),
            verdict=verdict,
            attack_pattern=pattern,
            action_taken=action,
            time_to_detect_ms=rng.randint(400, 2500) if verdict == "blocked" else 0,
            recommended_followups=["update_device_allowlist"],
            notes=ROUTINE_FALSE_POSITIVE_NOTES[profile.key],
            features_summary=_features(pattern, rng),
        )

    profile = rng.choice(ATTACK_DEVICES)
    pattern = rng.choices(
        list(ATTACK_PATTERN_WEIGHTS), weights=list(ATTACK_PATTERN_WEIGHTS.values())
    )[0]
    low, high = SCORE_RANGES[pattern]
    verdict = "suspicious" if roll < 0.16 else "blocked"
    if verdict == "suspicious":
        action = rng.choice(["alert_only", "none"])
        score = round(rng.uniform(THRESHOLD, THRESHOLD + 0.3), 3)
    else:
        action = rng.choices(
            ["locked_and_disabled", "device_disabled", "workstation_locked", "alert_only"],
            weights=[70, 10, 8, 12],
        )[0]
        score = round(rng.uniform(low, high), 3)
    ttd_low, ttd_high = TIME_TO_DETECT_RANGES_MS[pattern]
    return dict(
        device=_device_payload(profile, rng, detected_at),
        anomaly_score=score,
        verdict=verdict,
        attack_pattern=pattern,
        action_taken=action,
        time_to_detect_ms=rng.randint(ttd_low, ttd_high),
        recommended_followups=_attack_followups(rng, action),
        notes=rng.choice(ROUTINE_ATTACK_NOTES),
        features_summary=_features(pattern, rng),
    )


def generate_incidents(
    *,
    count: int = DEFAULT_COUNT,
    seed: int = DEFAULT_SEED,
    days: int = DEFAULT_DAYS,
    anchor: datetime | None = None,
) -> list[IncidentRecord]:
    """Seeded, reproducible synthetic incidents, oldest last-90-days spread.

    The first len(NOTABLE_INCIDENTS) records are the notable ones, in
    order; every record is validated by IncidentRecord on construction.
    """
    if count < len(NOTABLE_INCIDENTS):
        raise ValueError(f"count must be at least {len(NOTABLE_INCIDENTS)}")
    anchor = anchor or default_anchor()
    rng = random.Random(seed)
    incidents: list[IncidentRecord] = []

    for index in range(count):
        if index < len(NOTABLE_INCIDENTS):
            spec = dict(NOTABLE_INCIDENTS[index])
            detected_at = anchor - timedelta(days=spec.pop("days_ago"))
            profile = ALL_DEVICES[spec.pop("device")]
            fields = dict(
                device=_device_payload(profile, rng, detected_at),
                features_summary=_features(spec["attack_pattern"], rng),
                **spec,
            )
        else:
            detected_at = anchor - timedelta(seconds=rng.uniform(0, days * 86400))
            fields = _routine_incident(rng, detected_at)

        fields.setdefault("mitre_technique", MITRE_DEFAULT)
        incidents.append(
            IncidentRecord(
                incident_id=incident_id_for(seed, index),
                detected_at=detected_at,
                threshold=THRESHOLD,
                **fields,
            )
        )
    return incidents


def post_incidents(
    incidents: list[IncidentRecord],
    client: httpx.Client,
    token: str,
    *,
    retry_seconds: float = RATE_LIMIT_RETRY_SECONDS,
    sleep=time.sleep,
) -> Counter:
    """POST each incident to /incidents. Returns a Counter of outcomes.

    The connector rate-limits each client; a 429 is retried after
    retry_seconds rather than counted as a failure.
    """
    headers = {"Authorization": f"Bearer {token}"}
    outcomes: Counter = Counter()
    for incident in incidents:
        body = incident.model_dump(mode="json")
        for _attempt in range(RATE_LIMIT_MAX_RETRIES):
            response = client.post("/incidents", json=body, headers=headers)
            if response.status_code != 429:
                break
            sleep(retry_seconds)
        if response.status_code == 201:
            outcomes[response.json()["status"]] += 1
        else:
            outcomes[f"http_{response.status_code}"] += 1
            print(
                f"  {incident.incident_id}: HTTP {response.status_code} {response.text[:200]}",
                file=sys.stderr,
            )
    return outcomes


def summarise(incidents: list[IncidentRecord]) -> str:
    patterns = Counter(i.attack_pattern.value for i in incidents)
    actions = Counter(i.action_taken.value for i in incidents)
    false_positives = sum(1 for i in incidents if i.notes.startswith("False positive"))
    oldest = min(i.detected_at for i in incidents)
    newest = max(i.detected_at for i in incidents)
    return (
        f"{len(incidents)} incidents from {oldest:%Y-%m-%d} to {newest:%Y-%m-%d}\n"
        f"  attack patterns: {dict(patterns)}\n"
        f"  actions: {dict(actions)}\n"
        f"  false positives: {false_positives}"
    )


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--count", type=int, default=DEFAULT_COUNT)
    parser.add_argument("--seed", type=int, default=DEFAULT_SEED)
    parser.add_argument("--days", type=int, default=DEFAULT_DAYS)
    parser.add_argument(
        "--anchor",
        type=datetime.fromisoformat,
        default=None,
        help="ISO date the history counts back from (default: today, 00:00 UTC).",
    )
    parser.add_argument("--url", default=None, help="Connector base URL (default: from config).")
    parser.add_argument("--dry-run", action="store_true", help="Generate and summarise only.")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    if not 150 <= args.count <= 300:
        print("warning: the evaluation set assumes 150 to 300 incidents", file=sys.stderr)

    anchor = args.anchor
    if anchor is not None and anchor.tzinfo is None:
        anchor = anchor.replace(tzinfo=UTC)
    incidents = generate_incidents(count=args.count, seed=args.seed, days=args.days, anchor=anchor)
    print(summarise(incidents))
    if args.dry_run:
        return 0

    settings = get_settings()
    token_env_var = settings.connector.auth_token_env_var
    token = os.environ.get(token_env_var)
    if not token:
        print(f"error: set {token_env_var} to the connector's bearer token", file=sys.stderr)
        return 1

    base_url = args.url or f"http://{settings.connector.host}:{settings.connector.port}"
    try:
        with httpx.Client(base_url=base_url, timeout=10.0) as client:
            outcomes = post_incidents(incidents, client, token)
    except httpx.ConnectError:
        print(f"error: could not reach the connector at {base_url}; is it running?",
              file=sys.stderr)
        return 1

    print(f"posted to {base_url}: {dict(outcomes)}")
    print("The connector's RAG watcher ingests new incidents within a few seconds.")
    failures = sum(n for outcome, n in outcomes.items() if outcome.startswith("http_"))
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())

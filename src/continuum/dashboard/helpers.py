"""Pure formatting, filtering and shaping helpers for the dashboard.

Responsibility: everything the Streamlit pages compute that does not
need a live Streamlit session or a network call, so it can be unit
tested directly. No function here performs I/O.
"""

from __future__ import annotations

import re
from datetime import UTC, date, datetime, time, timedelta
from typing import Any

import pandas as pd

ROLLING_WINDOW_SECONDS = 60
INTERVAL_FEATURE = "flight_mean_ms"

VERDICT_ORDER = ("blocked", "suspicious", "normal", "idle")

RESPONSE_MODE_LABELS = {
    "alert_only": "Alert only",
    "lock_only": "Lock only",
    "lock_and_disable": "Lock and disable",
}

ATTACK_PATTERN_LABELS = {
    "burst_injection": "Burst injection",
    "slowed_injection": "Slowed injection",
    "randomized_injection": "Randomized injection",
    "unknown": "Unknown",
}


def parse_time(value: str | None) -> datetime | None:
    if not value:
        return None
    parsed = datetime.fromisoformat(value)
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    return parsed.astimezone(UTC)


def format_relative_age(value: str | datetime | None, *, now: datetime) -> str:
    """"12 s ago", "4 min ago", "3 h ago", "6 days ago"; "never" for None."""
    moment = parse_time(value) if isinstance(value, str) or value is None else value
    if moment is None:
        return "never"
    seconds = max(0, int((now - moment).total_seconds()))
    if seconds < 60:
        return f"{seconds} s ago"
    if seconds < 3600:
        return f"{seconds // 60} min ago"
    if seconds < 86400:
        return f"{seconds // 3600} h ago"
    days = seconds // 86400
    return f"{days} day ago" if days == 1 else f"{days} days ago"


def format_timestamp(value: str | None) -> str:
    moment = parse_time(value)
    return moment.strftime("%Y-%m-%d %H:%M:%S UTC") if moment else "unknown"


def mode_label(mode: str | None) -> str:
    if mode is None:
        return "unknown"
    return RESPONSE_MODE_LABELS.get(mode, mode)


def device_verdict(verdict: str | None, *, disabled: bool) -> str:
    """The badge to show: a disabled device is "blocked" whatever its last window said."""
    if disabled:
        return "blocked"
    if verdict in ("blocked", "suspicious", "normal"):
        return verdict
    return "idle"


def merge_devices(
    runtime_devices: list[dict[str, Any]], snapshots: list[dict[str, Any]]
) -> list[dict[str, Any]]:
    """One row per keyboard: attached devices from the runtime, joined with /live.

    A device with a live snapshot but no longer attached is still listed,
    since it was scored recently. Sorted blocked first, then suspicious.
    """
    by_id: dict[str, dict[str, Any]] = {}
    for device in runtime_devices:
        vendor_id = device.get("vendor_id", "????")
        product_id = device.get("product_id", "????")
        by_id[device["device_id"]] = {
            "device_id": device["device_id"],
            "name": device.get("name") or device["device_id"],
            "vendor_product": f"{vendor_id}:{product_id}",
            "bus_type": device.get("bus_type", ""),
            "disabled": bool(device.get("disabled")),
            "attached": True,
            "verdict": None,
            "anomaly_score": None,
            "threshold": None,
            "updated_at": None,
        }
    for snapshot in snapshots:
        row = by_id.setdefault(
            snapshot["device_id"],
            {
                "device_id": snapshot["device_id"],
                "name": snapshot["device_id"],
                "vendor_product": "",
                "bus_type": "",
                "disabled": False,
                "attached": False,
            },
        )
        row.update(
            verdict=snapshot.get("verdict"),
            anomaly_score=snapshot.get("anomaly_score"),
            threshold=snapshot.get("threshold"),
            updated_at=snapshot.get("updated_at"),
        )
    rows = list(by_id.values())
    for row in rows:
        row["badge"] = device_verdict(row.get("verdict"), disabled=row["disabled"])
    return sorted(rows, key=lambda r: (VERDICT_ORDER.index(r["badge"]), r["name"]))


def update_interval_history(
    history: list[dict[str, Any]],
    snapshots: list[dict[str, Any]],
    *,
    now: datetime,
    window_seconds: int = ROLLING_WINDOW_SECONDS,
) -> list[dict[str, Any]]:
    """Append new /live samples and drop anything older than the window.

    /live only holds each device's latest window, so the dashboard keeps
    its own short history by polling. Each point is stamped with the time
    the runtime scored it (updated_at), not the time it was polled, and a
    sample already in the history is not added twice.
    """
    seen = {(point["device_id"], point["updated_at"]) for point in history}
    merged = list(history)
    for snapshot in snapshots:
        interval = (snapshot.get("features") or {}).get(INTERVAL_FEATURE)
        updated_at = snapshot.get("updated_at")
        if interval is None or not updated_at:
            continue
        key = (snapshot["device_id"], updated_at)
        if key in seen:
            continue
        seen.add(key)
        merged.append(
            {
                "device_id": snapshot["device_id"],
                "updated_at": updated_at,
                "time": parse_time(updated_at),
                "interval_ms": float(interval),
                "verdict": snapshot.get("verdict"),
            }
        )
    cutoff = now - timedelta(seconds=window_seconds)
    return sorted(
        (point for point in merged if point["time"] >= cutoff), key=lambda p: p["time"]
    )


def short_device_label(device_id: str, names: dict[str, str]) -> str:
    return names.get(device_id) or device_id


def build_incident_params(
    *,
    start: date | None,
    end: date | None,
    verdict: str | None,
    attack_pattern: str | None,
    device_id: str | None,
    limit: int = 500,
) -> dict[str, Any]:
    """Query parameters for GET /incidents; the end date is inclusive."""
    params: dict[str, Any] = {"limit": limit}
    if start is not None:
        params["start_time"] = datetime.combine(start, time.min, tzinfo=UTC).isoformat()
    if end is not None:
        params["end_time"] = datetime.combine(end, time.max, tzinfo=UTC).isoformat()
    if verdict:
        params["verdict"] = verdict
    if attack_pattern:
        params["attack_pattern"] = attack_pattern
    if device_id and device_id.strip():
        params["device_id"] = device_id.strip()
    return params


def filter_by_text(items: list[dict[str, Any]], text: str) -> list[dict[str, Any]]:
    """Case-insensitive match on device name, device id, notes and incident id."""
    needle = text.strip().lower()
    if not needle:
        return items
    return [
        item
        for item in items
        if needle in item["device"]["name"].lower()
        or needle in item["device"]["device_id"].lower()
        or needle in (item.get("notes") or "").lower()
        or needle in item["incident_id"].lower()
    ]


def incidents_frame(items: list[dict[str, Any]]) -> pd.DataFrame:
    columns = [
        "detected_at",
        "device",
        "verdict",
        "attack_pattern",
        "anomaly_score",
        "action_taken",
        "time_to_detect_ms",
        "has_notes",
        "incident_id",
    ]
    rows = [
        {
            "detected_at": parse_time(item["detected_at"]),
            "device": item["device"]["name"],
            "verdict": item["verdict"],
            "attack_pattern": ATTACK_PATTERN_LABELS.get(
                item["attack_pattern"], item["attack_pattern"]
            ),
            "anomaly_score": round(float(item["anomaly_score"]), 3),
            "action_taken": item["action_taken"].replace("_", " "),
            "time_to_detect_ms": item["time_to_detect_ms"],
            "has_notes": bool(item.get("notes")),
            "incident_id": item["incident_id"],
        }
        for item in items
    ]
    return pd.DataFrame(rows, columns=columns)


def daily_counts(
    items: list[dict[str, Any]], *, start: date | None = None, end: date | None = None
) -> pd.DataFrame:
    """Incidents per UTC day, with zero-count days filled in, split by verdict."""
    if not items and (start is None or end is None):
        return pd.DataFrame(columns=["day", "verdict", "count"])

    days = [parse_time(item["detected_at"]).date() for item in items]
    first = start or min(days)
    last = end or max(days)
    counts: dict[tuple[date, str], int] = {}
    for item, day in zip(items, days, strict=True):
        key = (day, item["verdict"])
        counts[key] = counts.get(key, 0) + 1

    verdicts = sorted({item["verdict"] for item in items}) or ["blocked"]
    rows = []
    day = first
    while day <= last:
        for verdict in verdicts:
            count = counts.get((day, verdict), 0)
            rows.append({"day": pd.Timestamp(day), "verdict": verdict, "count": count})
        day += timedelta(days=1)
    return pd.DataFrame(rows, columns=["day", "verdict", "count"])


def question_about_incident(incident: dict[str, Any]) -> str:
    """A prefilled IncidentRAG question that names the incident unambiguously."""
    moment = parse_time(incident["detected_at"])
    when = moment.strftime("%Y-%m-%d %H:%M UTC") if moment else "an unknown time"
    pattern = ATTACK_PATTERN_LABELS.get(incident["attack_pattern"], incident["attack_pattern"])
    return (
        f"What happened in incident {incident['incident_id']} "
        f"({incident['device']['name']}, {pattern.lower()}, {incident['verdict']}, {when}), "
        "and what should I do next?"
    )


_MARKDOWN_SPECIALS = re.compile(r"[\[\]()!*_`<>#|\\]")


def plain_label(text: str) -> str:
    """Text for a Streamlit widget label, which renders markdown: strip its syntax."""
    return re.sub(r"\s+", " ", _MARKDOWN_SPECIALS.sub(" ", text)).strip()


def confidence_band(confidence: float, threshold: float) -> str:
    if confidence >= threshold + 0.2:
        return "high"
    if confidence >= threshold:
        return "moderate"
    return "low"


def sensitivity_description(sensitivity: int) -> str:
    if sensitivity == 5:
        return "Calibrated default"
    if sensitivity > 5:
        return "More alerts, more false positives"
    return "Fewer alerts, more risk of missing slow attacks"


def parse_allowlist_text(text: str) -> list[str]:
    """One device instance id per line; blank lines and duplicates dropped."""
    entries: list[str] = []
    for line in text.splitlines():
        entry = line.strip()
        if entry and entry not in entries:
            entries.append(entry)
    return entries


_TABLE_SEPARATOR = re.compile(r"^\|?\s*:?-{3,}:?\s*(\|\s*:?-{3,}:?\s*)*\|?\s*$")


def _split_row(line: str) -> list[str]:
    return [cell.strip() for cell in line.strip().strip("|").split("|")]


def parse_markdown_tables(markdown: str) -> list[pd.DataFrame]:
    """Every pipe table in a markdown document, as a DataFrame of strings."""
    lines = markdown.splitlines()
    tables: list[pd.DataFrame] = []
    index = 0
    while index < len(lines) - 1:
        is_header = lines[index].strip().startswith("|")
        if is_header and _TABLE_SEPARATOR.match(lines[index + 1].strip()):
            header = _split_row(lines[index])
            rows = []
            index += 2
            while index < len(lines) and lines[index].strip().startswith("|"):
                cells = _split_row(lines[index])
                rows.append((cells + [""] * len(header))[: len(header)])
                index += 1
            tables.append(pd.DataFrame(rows, columns=header))
        else:
            index += 1
    return tables


def markdown_prose(markdown: str) -> list[str]:
    """Plain paragraphs of a markdown document, without headings, tables or images.

    Line breaks inside a paragraph are kept, since docs/eval_results.md
    uses one line per fact in its header block.
    """
    paragraphs: list[str] = []
    for block in re.split(r"\n\s*\n", markdown):
        stripped = block.strip()
        if not stripped or stripped.startswith(("#", "|", "![")):
            continue
        paragraphs.append("\n".join(line.strip() for line in stripped.splitlines()))
    return paragraphs

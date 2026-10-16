"""Pure formatting, filtering and shaping helpers for the dashboard.

Responsibility: everything the Streamlit pages compute that does not
need a live Streamlit session or a network call, so it can be unit
tested directly. No function here performs I/O.
"""

from __future__ import annotations

import re
from datetime import UTC, date, datetime, time, timedelta
from pathlib import Path
from typing import Any

import pandas as pd

from continuum.common.schemas import TRIAL_MS_TO_BLOCK, TRIAL_MS_TO_LOCK, TRIAL_PRESSES_TO_BLOCK

ROLLING_WINDOW_SECONDS = 60
INTERVAL_FEATURE = "flight_mean_ms"

VERDICT_ORDER = ("blocked", "suspicious", "normal", "idle")

RESPONSE_MODE_LABELS = {
    "alert_only": "Alert only",
    "lock_only": "Lock only",
    "disable_only": "Disable device",
    "lock_and_disable": "Lock and disable",
}

ATTACK_PATTERN_LABELS = {
    "burst_injection": "Burst injection",
    "slowed_injection": "Slowed injection",
    "randomized_injection": "Randomized injection",
    "unknown": "Unknown",
}


REMOTE_RESPONSE_LABELS = {
    "alert_only": "alert only",
    "lock": "lock the PC",
    "lock_and_end_session": "lock the PC and end the remote session",
}


def remote_summary(status: dict[str, Any], *, now: datetime) -> dict[str, str]:
    """The Remote access card's state: a badge label and colour, and a hint line."""
    if not status.get("enabled"):
        return {"badge": "off", "colour": "gray", "hint": "Remote-access typing detection is off."}
    response = REMOTE_RESPONSE_LABELS.get(status.get("response", ""), status.get("response", ""))
    if status.get("allowed"):
        until = parse_time(status.get("allowed_until"))
        until_text = until.astimezone().strftime("%H:%M") if until else "soon"
        return {
            "badge": "allowed",
            "colour": "yellow",
            "hint": f"Remote typing is let through until {until_text}.",
        }
    tools = status.get("tools_running") or []
    if tools:
        return {
            "badge": "watching",
            "colour": "blue",
            "hint": f"Running now: {', '.join(tools)}. Remote typing will {response}.",
        }
    return {
        "badge": "protected",
        "colour": "green",
        "hint": f"No remote-access tool running. Remote typing would {response}.",
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


def blocked_note(device: dict[str, Any]) -> str:
    """How a blocked device is blocked, for its card; empty if it is not."""
    if not device.get("disabled"):
        return ""
    if device.get("quarantined"):
        return "blocked by Continuum, any key press locks the screen"
    return "disabled in Windows"


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
            "quarantined": bool(device.get("quarantined")),
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
                "quarantined": False,
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


def detection_timing_rows(incident: dict[str, Any]) -> list[tuple[str, str]]:
    """Time-to-detect rows for the incident detail panel.

    Incidents recorded by the current runtime also carry timings from the
    device's first key press; older or imported ones only have the
    suspicious-to-blocked figure.
    """
    summary = incident.get("features_summary") or {}
    rows: list[tuple[str, str]] = []
    if TRIAL_MS_TO_BLOCK in summary:
        presses = summary.get(TRIAL_PRESSES_TO_BLOCK)
        presses_text = f", {presses:.0f} key presses" if presses is not None else ""
        rows.append(
            ("First keystroke to block", f"{summary[TRIAL_MS_TO_BLOCK]:.0f} ms{presses_text}")
        )
    if TRIAL_MS_TO_LOCK in summary:
        rows.append(("First keystroke to lock", f"{summary[TRIAL_MS_TO_LOCK]:.0f} ms"))
    rows.append(("Suspicious to blocked", f"{incident['time_to_detect_ms']} ms"))
    return rows


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


def llm_disclosure(provider: str, rag_settings: Any) -> str:
    """One line telling the analyst which model writes answers, and where it runs."""
    if provider == "groq":
        return (
            f"Answers are written by {rag_settings.groq_model} on Groq's cloud API: your "
            "question and the retrieved incident and playbook text are sent to Groq."
        )
    return (
        f"Answers are written by {rag_settings.ollama_model}, running locally in Ollama; "
        "nothing leaves this machine."
    )


_SECTION_HEADING = re.compile(r"^##\s+(.+?)\s*$")
_MARKDOWN_INLINE = re.compile(r"[*_`]")


def typing_passages(corpus_dir: Path) -> list[str]:
    """Paragraphs for the Train page: each playbook's "When to use" section.

    Ordinary prose already in the corpus, flattened to one line with the
    markdown markup removed, so it is comfortable to type.
    """
    passages: list[str] = []
    for path in sorted(corpus_dir.rglob("*.md")):
        lines: list[str] = []
        inside = False
        for line in path.read_text(encoding="utf-8").splitlines():
            heading = _SECTION_HEADING.match(line)
            if heading:
                inside = heading.group(1).strip().lower() == "when to use"
                continue
            if inside:
                lines.append(line.strip())
        text = re.sub(r"\s+", " ", _MARKDOWN_INLINE.sub("", " ".join(lines))).strip()
        if text:
            passages.append(text)
    return passages


def passage_for_session(passages: list[str], saved_sessions: int) -> tuple[int, str]:
    """The next passage to type: a different one for each saved session, cycling."""
    if not passages:
        return 0, ""
    index = saved_sessions % len(passages)
    return index, passages[index]


def baseline_progress(n_windows: int, minimum: int, recommended: int) -> str:
    if n_windows >= recommended:
        return "Enough typing recorded. Train the model, or record more for a stronger baseline."
    if n_windows >= minimum:
        return (
            f"Enough to train. {recommended - n_windows} more windows reach the recommended "
            f"{recommended}."
        )
    return f"{minimum - n_windows} more windows needed before training is possible."


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

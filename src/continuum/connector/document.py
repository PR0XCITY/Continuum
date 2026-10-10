"""Turn an IncidentRecord into inert text for the RAG corpus.

Responsibility: the one place that decides what an incident "looks
like" as a document for IncidentRAG to retrieve later. Two rules this
module exists to enforce:

    - the document is built from a fixed template filled in with field
      values only; nothing from outside the schema-validated
      IncidentRecord ever reaches it, and nothing here is executable
      or interpreted as instructions by anything downstream,
    - free text (notes) is sanitised again here, server-side, even
      though common.schemas.IncidentRecord already sanitises it on
      construction; this is deliberate defense in depth; if that
      validator ever changed, this module's own pass still holds.

detect_suspicious_notes() is a cheap, deliberately over-inclusive
keyword check for the kind of phrasing a prompt-injection attempt in
`notes` would use. It never blocks or rewrites anything; it only sets
a flag the connector stores alongside the incident, so a human (or a
later, more careful IncidentRAG prompt) knows to treat that incident's
notes with suspicion. The notes still end up in the document below
verbatim (sanitised, length-limited), as inert data; flagging it is
not the same as refusing to store it.
"""

from __future__ import annotations

import re

from continuum.common.schemas import IncidentRecord

_CONTROL_CHAR_PATTERN = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
_MAX_NOTES_LENGTH = 280

_SUSPICIOUS_NOTE_PATTERNS = [
    re.compile(pattern, re.IGNORECASE)
    for pattern in (
        r"ignore (all |any )?previous instructions",
        r"ignore (the )?above",
        r"disregard (all |any )?previous",
        r"new instructions\s*:",
        r"system prompt",
        r"you are now",
        r"act as (a|an)\b",
        r"forget (everything|all|your instructions)",
        r"\bjailbreak\b",
        r"<\s*script\b",
        r"\bprompt injection\b",
        r"reveal your (instructions|prompt)",
    )
]

INCIDENT_DOCUMENT_TEMPLATE = """Incident {incident_id}
Detected at: {detected_at}
Device: {device_name} ({device_id}, {bus_type}, vendor {vendor_id} product {product_id})
Verdict: {verdict}
Attack pattern: {attack_pattern}
Anomaly score: {anomaly_score:.3f} (threshold {threshold:.3f})
Action taken: {action_taken}
Time to detect: {time_to_detect_ms} ms
MITRE technique: {mitre_technique}
Recommended followups: {recommended_followups}
Notes: {notes}
"""


def sanitise_notes(notes: str) -> str:
    """Strip control characters and cap length. Safe to call more than once."""
    if not isinstance(notes, str):
        return ""
    return _CONTROL_CHAR_PATTERN.sub("", notes).strip()[:_MAX_NOTES_LENGTH]


def detect_suspicious_notes(notes: str) -> bool:
    """True if notes contains phrasing typical of a prompt-injection attempt.

    A heuristic, not a guarantee; false positives are expected and
    harmless (the note is still stored, just flagged), false negatives
    are possible (an attacker who avoids these exact phrases). This is
    a visibility aid, not the system's actual defense against prompt
    injection; that defense is that this text is never treated as
    instructions anywhere downstream, only ever as quoted data in a
    fixed template.
    """
    if not notes:
        return False
    return any(pattern.search(notes) for pattern in _SUSPICIOUS_NOTE_PATTERNS)


def render_incident_document(incident: IncidentRecord) -> str:
    """Plain text, field values only, for the RAG ingest queue.

    Never ingests a raw request body or any text that did not pass
    through IncidentRecord's own schema validation first.
    """
    recommended_followups = (
        ", ".join(followup.value for followup in incident.recommended_followups) or "none"
    )
    return INCIDENT_DOCUMENT_TEMPLATE.format(
        incident_id=str(incident.incident_id),
        detected_at=incident.detected_at.isoformat(),
        device_name=incident.device.name,
        device_id=incident.device.device_id,
        bus_type=incident.device.bus_type,
        vendor_id=incident.device.vendor_id,
        product_id=incident.device.product_id,
        verdict=incident.verdict,
        attack_pattern=incident.attack_pattern.value,
        anomaly_score=incident.anomaly_score,
        threshold=incident.threshold,
        action_taken=incident.action_taken.value,
        time_to_detect_ms=incident.time_to_detect_ms,
        mitre_technique=incident.mitre_technique,
        recommended_followups=recommended_followups,
        notes=sanitise_notes(incident.notes),
    )

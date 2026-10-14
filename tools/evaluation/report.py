"""Assemble docs/EVALUATION.md from the section results."""

from __future__ import annotations

import subprocess
from datetime import UTC, datetime
from pathlib import Path

from continuum.detection.features import DEFAULT_WINDOW_SIZE, DEFAULT_WINDOW_STEP
from continuum.detection.model import DEFAULT_TARGET_FALSE_POSITIVE_RATE
from continuum.detection.scorer import DEFAULT_NEW_DEVICE_GRACE_PERIOD_SECONDS
from tools.evaluation.common import SectionResult, fmt
from tools.evaluation.detector import BaselineData, minimum_presses_to_block
from tools.simulate_attacks import DEFAULT_BURST_INTERVAL_RANGE_MS

REPO_ROOT = Path(__file__).resolve().parents[2]


def git_revision() -> str:
    try:
        commit = subprocess.run(
            ["git", "rev-parse", "--short", "HEAD"],
            cwd=REPO_ROOT, capture_output=True, text=True, check=True,
        ).stdout.strip()
        dirty = subprocess.run(
            ["git", "status", "--porcelain"],
            cwd=REPO_ROOT, capture_output=True, text=True, check=True,
        ).stdout.strip()
    except (OSError, subprocess.CalledProcessError):
        return "unknown"
    return f"{commit} with uncommitted changes" if dirty else commit


def _get(facts: dict, *path: str, default: object = None) -> object:
    node: object = facts
    for key in path:
        if not isinstance(node, dict) or key not in node:
            return default
        node = node[key]
    return node


def limitations(facts: dict, baseline: BaselineData) -> str:
    minimum = minimum_presses_to_block()
    fastest, slowest = DEFAULT_BURST_INTERVAL_RANGE_MS
    items: list[str] = []

    randomized_all = _get(facts, "window_recall", "randomized_injection")
    randomized_timing = _get(facts, "ablation_recall", "timing only", "randomized_injection")
    slowed_timing = _get(facts, "ablation_recall", "timing only", "slowed_injection")
    items.append(
        "**Slowed and randomized injection get past timing features.** Randomized injection, "
        "typed at a human-like average speed with human-like spread, is largely missed: "
        f"window-level recall {fmt(randomized_all, 2)} with all features and "
        f"{fmt(randomized_timing, 2)} with timing features alone. Slowed injection is caught "
        f"(timing-only recall {fmt(slowed_timing, 2)}) only because its spacing is perfectly "
        "even, which no person produces; a slowed payload with a little added jitter becomes "
        "the randomized case. What separates the two in the ablation is mostly dwell and "
        "rollover, which an injection tool that also randomises key hold times would remove. "
        "Catching a careful attacker reliably needs signals beyond keystroke timing."
    )

    landed = _get(facts, "hardware_chars_landed") or {}
    e2e_presses = _get(facts, "e2e_presses", "mean")
    measured = []
    if e2e_presses is not None:
        measured.append(
            f"in the end-to-end replay, {fmt(e2e_presses, 0)} keystrokes were typed before "
            "the block"
        )
    if landed:
        measured.append(
            "on real hardware, an average of "
            + ", ".join(f"{fmt(v, 0)} characters for {p}" for p, v in landed.items())
            + " landed in the editor"
        )
    measured_text = ("; ".join(measured) + ". ") if measured else ""
    measured_text = measured_text[:1].upper() + measured_text[1:]
    items.append(
        "**Raw Input is observe-only, so keystrokes land before containment.** Raw Input "
        "gives Continuum a copy of each keystroke; it cannot hold back, delay or drop one. "
        "Every keystroke typed before the workstation locks reaches the focused window. The "
        f"detector needs a full {DEFAULT_WINDOW_SIZE}-press window, and blocking needs a "
        f"second flagged window {DEFAULT_WINDOW_STEP} presses later, so nothing can be "
        f"blocked before the {minimum}th key press: at burst speed ({fastest:.0f} to "
        f"{slowest:.0f} ms per key) that is {minimum * fastest:.0f} to "
        f"{minimum * slowest:.0f} ms of typing that always lands. {measured_text}A payload "
        f"shorter than {minimum} keystrokes, for example opening the Run dialog and typing a "
        "short command, is never detected at all."
    )

    fpr = _get(facts, "window_fpr")
    fp_sessions = _get(facts, "fp_sessions") or []
    fp_text = "; ".join(
        f"{s['label']}: {fmt(s['blocks_per_hour'], 1)} false blocks per hour"
        for s in fp_sessions
    )
    if baseline.source == "synthetic":
        baseline_text = (
            "No recorded baseline was available for this run, so the detector was trained and "
            "tested on simulated typing only; none of the HID Firewall numbers above say how "
            "it behaves for a real person. "
        )
    else:
        baseline_text = (
            f"The recorded baseline has {baseline.n_windows} windows. With 20 percent held "
            "back for calibration, the 1 percent false positive threshold is set from only "
            f"about {round(baseline.n_windows * 0.8 * 0.2)} windows, so it rests on one or "
            "two of the most unusual ones. "
        )
    items.append(
        "**The baseline is small.** "
        + baseline_text
        + f"The model targets a {DEFAULT_TARGET_FALSE_POSITIVE_RATE:.0%} window false "
        f"positive rate; on held-out windows it measured {fmt(fpr, 3)}. "
        + (f"Replayed typing gave {fp_text}. " if fp_text else "")
        + "Typing faster than anything in the baseline is the main source of false blocks; "
        "a baseline should include a deliberately fast session."
    )

    items.append(
        "**The Digispark bootloader delays every attack, and the timings here exclude it.** "
        "After being plugged in, a Digispark runs its bootloader for about 5 seconds, "
        "enumerating as a different USB device, before re-enumerating as a keyboard and "
        "running the sketch, which waits a further 3 to 10 seconds. Continuum sees no "
        "keystrokes during that time, so it has nothing to detect, and every timing in this "
        "document starts at the first keystroke: plug-in to lock is several seconds longer "
        "than the figures above. The re-enumerated keyboard counts as a new device, so the "
        f"stricter new-device threshold applies for its first "
        f"{DEFAULT_NEW_DEVICE_GRACE_PERIOD_SECONDS:.0f} seconds of typing."
    )

    gate = _get(facts, "rag_full_gate") or _get(facts, "rag_retrieval_gate")
    if gate and gate["answerable"] and gate["wrongly_abstained"] / gate["answerable"] > 0.25:
        which = (
            "The full confidence gate"
            if _get(facts, "rag_full_gate")
            else "The confidence gate, scored on retrieval alone,"
        )
        caveat = (
            ""
            if _get(facts, "rag_full_gate")
            else " In production the gate also scores how well the answer's sentences match "
            "their cited sources, which can raise confidence; that part was not measurable "
            "here, so this may overstate the problem."
        )
        items.append(
            f"**IncidentRAG refuses too often.** {which} abstained on "
            f"{gate['wrongly_abstained']} of {gate['answerable']} answerable questions while "
            "catching every unanswerable one. Refusing is the safe failure, but at this rate "
            "an analyst gets \"insufficient evidence\" for many questions the corpus does "
            "answer; the 0.5 threshold and the gate's weights need tuning against this "
            f"question set.{caveat}"
        )

    if not _get(facts, "llm_available", default=False):
        items.append(
            "**IncidentRAG's answers were not evaluated in this run.** The configured LLM was "
            "not available, so answer quality, citation validity and the full confidence "
            "gate are unmeasured; only retrieval and the retrieval-only gate were."
        )

    return "\n\n".join(f"{i}. {item}" for i, item in enumerate(items, start=1))


def assemble(
    *,
    sections: dict[str, SectionResult],
    baseline: BaselineData,
    data_lines: list[str],
    seeds: list[int],
    command: str,
) -> str:
    facts: dict[str, object] = {}
    for section in sections.values():
        facts.update(section.facts)

    def body(key: str) -> str:
        section = sections.get(key)
        if section is None:
            return "_Not run (skipped on the command line)._\n"
        return section.markdown

    data_md = "\n".join(f"- {line}" for line in data_lines)
    generated = datetime.now(UTC).strftime("%Y-%m-%d %H:%M UTC")
    return f"""# Continuum evaluation

Generated by `tools/evaluate_all.py` on {generated}, from commit {git_revision()}.
Regenerate with `{command}`. Figures are in `docs/figures/`.

## Data used

{data_md}
- Simulation seeds: {", ".join(str(s) for s in seeds)}.

## 1. HID Firewall

### 1.1 Simulated attack streams

{body("simulated")}
### 1.2 Feature ablation

{body("ablation")}
### 1.3 False positive study

{body("false_positives")}
### 1.4 Hardware trials

{body("hardware")}
## 2. IncidentRAG

{body("rag")}
## 3. End to end

{body("end_to_end")}
## 4. Limitations

{limitations(facts, baseline)}
"""

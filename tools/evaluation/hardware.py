"""Real Digispark trial results, read from docs/hardware_trial_results.csv.

The CSV is written by tools/run_hardware_trial.py, one row per run,
including runs where no incident appeared (detected = 0), so detection
rate per payload is runs detected over runs attempted.
"""

from __future__ import annotations

import csv
from pathlib import Path

from tools.evaluation.common import (
    PALETTE,
    SectionResult,
    distribution,
    fmt,
    md_table,
    new_figure,
    save_figure,
)
from tools.run_hardware_trial import CSV_FIELDS, PAYLOAD_CHARS, PAYLOADS


def _number(value: str) -> float | None:
    value = (value or "").strip()
    return float(value) if value else None


def read_trials(path: Path) -> list[dict[str, str]]:
    with path.open(encoding="utf-8", newline="") as handle:
        reader = csv.DictReader(handle)
        if reader.fieldnames != CSV_FIELDS:
            raise ValueError(
                f"{path} does not have the columns tools/run_hardware_trial.py writes; "
                "it was probably recorded by an older version"
            )
        return list(reader)


def summarise_trials(rows: list[dict[str, str]]) -> dict[str, dict[str, object]]:
    """Per payload: run counts, detection rate and timing distributions."""
    payloads = [p for p in PAYLOADS if any(r["payload"] == p for r in rows)]
    payloads += sorted({r["payload"] for r in rows} - set(payloads))
    summary: dict[str, dict[str, object]] = {}
    for payload in payloads:
        runs = [r for r in rows if r["payload"] == payload]
        detected = [r for r in runs if r["detected"] == "1"]

        def values(column: str, source: list[dict[str, str]] = detected) -> list[float]:
            return [v for v in (_number(r[column]) for r in source) if v is not None]

        summary[payload] = {
            "runs": len(runs),
            "detected": len(detected),
            "detection_rate": len(detected) / len(runs) if runs else float("nan"),
            "presses_to_block": distribution(values("presses_to_block")),
            "ms_to_block": distribution(values("ms_to_block")),
            "ms_to_lock": distribution(values("ms_to_lock")),
            "chars_landed": distribution(values("chars_landed", runs)),
            "chars_landed_counted": len(values("chars_landed", runs)),
        }
    return summary


def _dist_cells(stats: dict[str, float], digits: int = 0) -> list[str]:
    return [fmt(stats["mean"], digits), fmt(stats["median"], digits), fmt(stats["p95"], digits)]


def hardware_section(csv_path: Path, figures_dir: Path) -> SectionResult:
    if not csv_path.exists():
        return SectionResult(
            f"""No hardware trial data yet: `{csv_path.name}` does not exist. To produce it,
flash the sketches in `tools/attacks/` (see its README for the safe procedure), start the
runtime and the connector, and run `python tools/run_hardware_trial.py`, doing five runs per
payload. Each run records whether an incident appeared, key presses and milliseconds from the
first injected keystroke to the block and to the lock, and how many of the {PAYLOAD_CHARS}
payload characters you saw land in the editor. Rerun this script afterwards and this section
fills in.
""",
            status="skipped",
        )

    rows = read_trials(csv_path)
    if not rows:
        return SectionResult(f"`{csv_path.name}` exists but has no runs yet.", status="skipped")
    summary = summarise_trials(rows)

    detection_rows = [
        [
            payload,
            str(s["runs"]),
            str(s["detected"]),
            fmt(s["detection_rate"], 2),
            *_dist_cells(s["presses_to_block"]),
            *_dist_cells(s["ms_to_block"]),
            *_dist_cells(s["ms_to_lock"]),
        ]
        for payload, s in summary.items()
    ]
    detection_table = md_table(
        [
            "payload",
            "runs",
            "detected",
            "detection rate",
            "presses to block (mean)",
            "(median)",
            "(p95)",
            "ms to block (mean)",
            "(median)",
            "(p95)",
            "ms to lock (mean)",
            "(median)",
            "(p95)",
        ],
        detection_rows,
    )

    landed_rows = []
    for payload, s in summary.items():
        landed = s["chars_landed"]
        if not s["chars_landed_counted"]:
            landed_rows.append([payload, "0", "n/a", "n/a", "n/a", "n/a"])
            continue
        landed_rows.append(
            [
                payload,
                str(s["chars_landed_counted"]),
                fmt(landed["mean"], 1),
                fmt(landed["median"], 1),
                fmt(landed["max"], 0),
                f"{landed['mean'] / PAYLOAD_CHARS:.0%}",
            ]
        )
    landed_table = md_table(
        ["payload", "runs counted", "mean", "median", "max", "mean share of payload"],
        landed_rows,
    )

    fig, ax = new_figure(7, 3.8)
    series = [
        [_number(r["ms_to_block"]) for r in rows if r["payload"] == p and r["ms_to_block"]]
        for p in summary
    ]
    plotted = [(p, s) for p, s in zip(summary, series, strict=True) if s]
    if plotted:
        box = ax.boxplot([s for _, s in plotted], patch_artist=True, widths=0.5)
        for patch, colour in zip(box["boxes"], PALETTE, strict=False):
            patch.set_facecolor(colour)
            patch.set_alpha(0.35)
        ax.set_xticks(range(1, len(plotted) + 1), [p for p, _ in plotted])
    ax.set_ylabel("ms from first injected keystroke to block")
    ax.set_title("Hardware trials: time to block")
    figure = save_figure(fig, figures_dir, "hardware_time_to_block.png")

    lock_note = ""
    if all(not s["ms_to_lock"]["n"] for s in summary.values()):
        lock_note = (
            "\nNo run recorded a lock time, which means the runtime was in a response mode that "
            "does not lock (alert only, or not elevated with lock disabled).\n"
        )
    markdown = f"""Real runs with a Digispark ATtiny85 typing the harmless {PAYLOAD_CHARS}-character
payload from `tools/attacks/`. Timings are measured from the device's first key press, on
the capture clock, so the Digispark's bootloader and startup delays (several seconds before
the first keystroke) are not counted. Time to lock adds the measured duration of the
LockWorkStation call to the time to block.

{detection_table}
{lock_note}
#### Characters that landed before the response

Counted by eye in the editor after each run (Continuum itself never records which keys
were typed). An undetected run normally lands the whole payload.

{landed_table}

![Hardware trials: time to block]({figure})
"""
    detected_rates = {p: s["detection_rate"] for p, s in summary.items()}
    landed_means = {
        p: s["chars_landed"]["mean"] for p, s in summary.items() if s["chars_landed_counted"]
    }
    return SectionResult(
        markdown,
        facts={"hardware_detection_rate": detected_rates, "hardware_chars_landed": landed_means},
    )

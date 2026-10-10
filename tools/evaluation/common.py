"""Small shared helpers: markdown tables, number formatting, statistics, figures."""

from __future__ import annotations

import math
from collections.abc import Sequence
from dataclasses import dataclass, field
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402
import numpy as np  # noqa: E402

FIGURE_DPI = 140
INK = "#2F3437"
MUTED = "#787774"
PALETTE = ["#2F3437", "#1F6C9F", "#9F2F2D", "#346538", "#956400", "#787774"]


@dataclass
class SectionResult:
    """One report section: its markdown, whether it ran, and facts for Limitations."""

    markdown: str
    status: str = "ok"  # "ok", "skipped" (missing optional input) or "failed"
    facts: dict[str, object] = field(default_factory=dict)


def fmt(value: object, digits: int = 3) -> str:
    if value is None:
        return "n/a"
    if isinstance(value, float):
        if math.isnan(value):
            return "n/a"
        return f"{value:.{digits}f}"
    return str(value)


def fmt_mean_std(values: Sequence[float], digits: int = 3) -> str:
    finite = [v for v in values if not math.isnan(v)]
    if not finite:
        return "n/a"
    if len(finite) == 1:
        return f"{finite[0]:.{digits}f}"
    return f"{np.mean(finite):.{digits}f} ± {np.std(finite):.{digits}f}"


def md_table(headers: Sequence[str], rows: Sequence[Sequence[object]]) -> str:
    def cell(value: object) -> str:
        return (value if isinstance(value, str) else fmt(value)).replace("|", "\\|")

    lines = [
        "| " + " | ".join(headers) + " |",
        "| " + " | ".join("---" for _ in headers) + " |",
    ]
    lines += ["| " + " | ".join(cell(v) for v in row) + " |" for row in rows]
    return "\n".join(lines)


def distribution(values: Sequence[float]) -> dict[str, float]:
    """n, mean, median, p95, min and max; NaN for an empty sequence."""
    array = np.asarray([v for v in values if v is not None and not math.isnan(v)], dtype=float)
    if array.size == 0:
        nan = float("nan")
        return {"n": 0, "mean": nan, "median": nan, "p95": nan, "min": nan, "max": nan}
    return {
        "n": int(array.size),
        "mean": float(array.mean()),
        "median": float(np.median(array)),
        "p95": float(np.percentile(array, 95)),
        "min": float(array.min()),
        "max": float(array.max()),
    }


def new_figure(width: float = 7.0, height: float = 4.0):
    fig, ax = plt.subplots(figsize=(width, height))
    for side in ("top", "right"):
        ax.spines[side].set_visible(False)
    for side in ("left", "bottom"):
        ax.spines[side].set_color("#BBBBBB")
    ax.tick_params(colors=INK)
    ax.grid(axis="y", color="#EAEAEA", linewidth=0.8)
    ax.set_axisbelow(True)
    return fig, ax


def save_figure(fig, figures_dir: Path, name: str) -> str:
    """Save to figures_dir/name and return the path relative to docs/."""
    figures_dir.mkdir(parents=True, exist_ok=True)
    fig.tight_layout()
    fig.savefig(figures_dir / name, dpi=FIGURE_DPI)
    plt.close(fig)
    return f"{figures_dir.name}/{name}"

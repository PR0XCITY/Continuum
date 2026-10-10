"""Run every Continuum evaluation and regenerate docs/EVALUATION.md.

Usage:
    python tools/evaluate_all.py [--user NAME] [--seeds 5] [--e2e-runs 5]
                                 [--no-llm] [--skip-rag] [--skip-e2e]

Sections, each described in its own module under tools/evaluation/:
    HID Firewall   simulated attacks over several seeds, feature ablation,
                   false positive study, hardware trials (from
                   docs/hardware_trial_results.csv, when it exists).
    IncidentRAG    retrieval hit rate and MRR, the confidence gate, and,
                   when the local Ollama model is installed, answers,
                   citations and wrong-confident answers with and without
                   the gate.
    End to end     first injected keystroke to incident visible and
                   retrievable, through the real runtime and connector code.

Optional inputs that are missing (a recorded baseline, hardware trial
data, the Ollama model) are reported in the document as such, never
filled in with guesses. A section that crashes is written up as failed
and makes the script exit with status 1; the document is still written.
Writes docs/EVALUATION.md and docs/figures/*.png. Never touches
data/db or data/chroma; RAG and end-to-end runs use temporary stores.
"""

from __future__ import annotations

import argparse
import getpass
import sys
import tempfile
import time
import traceback
from collections.abc import Callable
from pathlib import Path

# tools/ is not installed; running this file directly needs the repo root on sys.path.
REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from continuum.common.config import get_settings  # noqa: E402
from continuum.detection.baseline import DEFAULT_BASELINE_DIR  # noqa: E402
from continuum.rag.ingest import resolve_corpus_path  # noqa: E402
from tools.evaluation import detector, end_to_end, hardware, rag_eval, report  # noqa: E402
from tools.evaluation.common import SectionResult  # noqa: E402

DOCS_DIR = REPO_ROOT / "docs"
DEFAULT_OUTPUT = DOCS_DIR / "EVALUATION.md"
DEFAULT_HARDWARE_CSV = DOCS_DIR / "hardware_trial_results.csv"
DEFAULT_QUESTIONS = REPO_ROOT / "data" / "eval" / "rag_questions.yaml"


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--user", default=getpass.getuser(),
                        help="whose recorded baseline to use (default: the OS user)")
    parser.add_argument("--seeds", type=int, default=5, help="simulation seeds (default 5)")
    parser.add_argument("--e2e-runs", type=int, default=5, help="end-to-end runs (default 5)")
    parser.add_argument("--no-llm", action="store_true", help="never call Ollama")
    parser.add_argument("--skip-rag", action="store_true")
    parser.add_argument("--skip-e2e", action="store_true")
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--hardware-csv", type=Path, default=DEFAULT_HARDWARE_CSV)
    parser.add_argument("--questions", type=Path, default=DEFAULT_QUESTIONS)
    return parser.parse_args(argv)


def run_section(name: str, build: Callable[[], SectionResult]) -> SectionResult:
    print(f"[{name}] running...", flush=True)
    started = time.perf_counter()
    try:
        result = build()
    except Exception as error:
        traceback.print_exc()
        result = SectionResult(
            f"**This section failed:** `{error.__class__.__name__}: {error}`. See the console "
            "output of `tools/evaluate_all.py` for the traceback.\n",
            status="failed",
        )
    print(f"[{name}] {result.status} in {time.perf_counter() - started:.1f} s", flush=True)
    return result


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    settings = get_settings()
    figures_dir = args.output.parent / "figures"
    seeds = list(range(args.seeds))
    corpus_path = resolve_corpus_path(settings)

    baseline = detector.load_baseline_data(args.user)
    print(f"Baseline: {baseline.source}, {baseline.n_windows} windows")
    streams = detector.AttackStreams()
    sections: dict[str, SectionResult] = {}

    sections["simulated"] = run_section(
        "simulated attacks",
        lambda: detector.simulated_section(baseline, seeds, streams, figures_dir),
    )
    sections["ablation"] = run_section(
        "feature ablation",
        lambda: detector.ablation_section(baseline, seeds, streams, figures_dir),
    )
    sections["false_positives"] = run_section(
        "false positive study",
        lambda: detector.false_positive_section(
            baseline, user=args.user, baseline_dir=DEFAULT_BASELINE_DIR, figures_dir=figures_dir
        ),
    )
    sections["hardware"] = run_section(
        "hardware trials", lambda: hardware.hardware_section(args.hardware_csv, figures_dir)
    )

    with tempfile.TemporaryDirectory(prefix="continuum-eval-", ignore_cleanup_errors=True) as tmp:
        workdir = Path(tmp)
        if not args.skip_rag:
            sections["rag"] = run_section(
                "IncidentRAG",
                lambda: rag_eval.rag_section(
                    questions_path=args.questions,
                    corpus_path=corpus_path,
                    settings=settings,
                    workdir=workdir / "rag",
                    figures_dir=figures_dir,
                    try_llm=not args.no_llm,
                ),
            )
        if not args.skip_e2e:
            (workdir / "e2e").mkdir()
            sections["end_to_end"] = run_section(
                "end to end",
                lambda: end_to_end.end_to_end_section(
                    model=detector.fit_model(baseline, baseline.features),
                    settings=settings,
                    corpus_path=corpus_path,
                    workdir=workdir / "e2e",
                    figures_dir=figures_dir,
                    runs=args.e2e_runs,
                ),
            )

    data_lines = detector.data_source_lines(baseline, args.user)
    data_lines.append(
        "Hardware trials: "
        + (f"`{args.hardware_csv.name}`." if args.hardware_csv.exists() else "none recorded yet.")
    )
    llm_available = sections.get("rag", SectionResult("")).facts.get("llm_available")
    data_lines.append(
        "IncidentRAG answers: "
        + ("generated by the local Ollama model." if llm_available else
           f"not generated (model `{settings.rag.ollama_model}` unavailable or disabled).")
    )

    command = "python tools/evaluate_all.py" + "".join(
        f" {flag}" for flag, on in (("--no-llm", args.no_llm), ("--skip-rag", args.skip_rag),
                                    ("--skip-e2e", args.skip_e2e)) if on
    )
    document = report.assemble(
        sections=sections, baseline=baseline, data_lines=data_lines, seeds=seeds, command=command
    )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(document, encoding="utf-8")
    print(f"Wrote {args.output}")

    failed = [name for name, section in sections.items() if section.status == "failed"]
    if failed:
        print(f"Failed sections: {', '.join(failed)}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

"""Tests for tools/evaluate_all.py and the tools/evaluation package.

Covers the pure pieces (statistics, tables, trial CSV summaries,
abstention metrics, window time reconstruction, the Limitations text)
and one fast end-to-end run of evaluate_all.main with the slow sections
skipped or shrunk. The full run, with the embedding model and the live
connector, is the acceptance check: python tools/evaluate_all.py.
"""

from __future__ import annotations

import csv
import math
from datetime import UTC, datetime

import numpy as np
import pytest
from tools import evaluate_all
from tools.evaluation import detector, hardware, rag_eval, report
from tools.evaluation.common import distribution, fmt, fmt_mean_std, md_table
from tools.run_hardware_trial import CSV_FIELDS, PAYLOAD_CHARS

from continuum.detection.features import FEATURE_NAMES
from continuum.rag.retrieve import RetrievedChunk

EM_DASH = chr(0x2014)

# --- common -----------------------------------------------------------------------


def test_distribution_reports_mean_median_and_p95():
    stats = distribution(list(range(1, 101)))

    assert stats["n"] == 100
    assert stats["mean"] == pytest.approx(50.5)
    assert stats["median"] == pytest.approx(50.5)
    assert stats["p95"] == pytest.approx(95.05)


def test_distribution_of_nothing_is_nan():
    stats = distribution([])
    assert stats["n"] == 0
    assert math.isnan(stats["mean"])


def test_formatting_handles_missing_values():
    assert fmt(None) == "n/a"
    assert fmt(float("nan")) == "n/a"
    assert fmt(0.12345, 2) == "0.12"
    assert fmt_mean_std([0.5]) == "0.500"
    assert fmt_mean_std([float("nan")]) == "n/a"


def test_md_table_escapes_pipes():
    table = md_table(["a", "b"], [["x|y", 1.0]])
    assert "x\\|y" in table
    assert table.splitlines()[1] == "| --- | --- |"


# --- detector ---------------------------------------------------------------------


def test_minimum_presses_to_block_is_window_plus_one_step():
    assert detector.minimum_presses_to_block() == 40


def test_feature_subsets_partition_the_feature_set():
    timing = set(detector.TIMING_ONLY)
    dwell = set(detector.ROLLOVER_AND_DWELL)
    assert timing.isdisjoint(dwell)
    assert timing | dwell == set(FEATURE_NAMES)
    assert "rollover_ratio" in dwell


def test_recorded_windows_spread_out_windows_that_share_a_sitting_timestamp():
    moment = datetime(2026, 1, 1, tzinfo=UTC)
    features = np.ones((3, len(FEATURE_NAMES)))
    features[:, FEATURE_NAMES.index("flight_mean_ms")] = 100.0
    baseline = detector.BaselineData(
        "recorded", "u", "kbd", features, list(FEATURE_NAMES), [moment] * 3
    )

    windows = detector.recorded_windows(baseline, [2, 0, 1], FEATURE_NAMES)

    starts = [w.window_start_ns for w in windows]
    # 10 presses at 100 ms apart: one second between consecutive windows.
    assert np.diff(starts).tolist() == [1_000_000_000, 1_000_000_000]


def test_missing_recorded_baseline_falls_back_to_synthetic(tmp_path):
    baseline = detector.load_baseline_data("nobody", baseline_dir=tmp_path)

    assert baseline.source == "synthetic"
    assert baseline.n_windows > 100
    assert "synthetic" in detector.data_source_lines(baseline, "nobody")[0]


# --- hardware ---------------------------------------------------------------------


def _write_trials(path, rows):
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=CSV_FIELDS)
        writer.writeheader()
        for row in rows:
            writer.writerow({field: row.get(field, "") for field in CSV_FIELDS})


def test_summarise_trials_counts_detection_rate_and_timings():
    rows = [
        {"payload": "burst", "detected": "1", "presses_to_block": "40", "ms_to_block": "200",
         "ms_to_lock": "220", "chars_landed": "41"},
        {"payload": "burst", "detected": "1", "presses_to_block": "50", "ms_to_block": "300",
         "ms_to_lock": "", "chars_landed": ""},
        {"payload": "randomized", "detected": "0", "presses_to_block": "", "ms_to_block": "",
         "ms_to_lock": "", "chars_landed": str(PAYLOAD_CHARS)},
    ]
    rows = [{field: r.get(field, "") for field in CSV_FIELDS} for r in rows]

    summary = hardware.summarise_trials(rows)

    assert summary["burst"]["detection_rate"] == 1.0
    assert summary["burst"]["presses_to_block"]["mean"] == 45.0
    assert summary["burst"]["ms_to_lock"]["n"] == 1
    assert summary["burst"]["chars_landed_counted"] == 1
    assert summary["randomized"]["detection_rate"] == 0.0
    assert summary["randomized"]["chars_landed"]["mean"] == PAYLOAD_CHARS


def test_hardware_section_without_data_is_skipped(tmp_path):
    result = hardware.hardware_section(tmp_path / "missing.csv", tmp_path / "figures")

    assert result.status == "skipped"
    assert "run_hardware_trial.py" in result.markdown


def test_hardware_section_with_data_reports_tables_and_a_figure(tmp_path):
    csv_path = tmp_path / "trials.csv"
    _write_trials(
        csv_path,
        [
            {"payload": "burst", "detected": "1", "presses_to_block": "40",
             "ms_to_block": "210", "ms_to_lock": "230", "chars_landed": "40"},
            {"payload": "burst", "detected": "0", "chars_landed": str(PAYLOAD_CHARS)},
        ],
    )

    result = hardware.hardware_section(csv_path, tmp_path / "figures")

    assert result.status == "ok"
    assert "| burst | 2 | 1 | 0.50 |" in result.markdown
    assert (tmp_path / "figures" / "hardware_time_to_block.png").exists()
    assert result.facts["hardware_detection_rate"]["burst"] == 0.5


def test_hardware_section_refuses_an_old_csv_layout(tmp_path):
    csv_path = tmp_path / "trials.csv"
    csv_path.write_text("payload,time_to_lock_ms\nburst,10\n", encoding="utf-8")

    with pytest.raises(ValueError):
        hardware.hardware_section(csv_path, tmp_path / "figures")


# --- rag --------------------------------------------------------------------------


def _chunk(doc_id):
    return RetrievedChunk(doc_id + ":0", doc_id, "playbook", doc_id, "t", 0, "text", 1.0, 0.5)


def test_doc_ranking_deduplicates_in_order():
    chunks = [_chunk("a"), _chunk("b"), _chunk("a"), _chunk("c")]
    assert rag_eval.doc_ranking(chunks) == ["a", "b", "c"]


def test_reciprocal_rank_and_hits():
    question = rag_eval.EvalQuestion("pb-01", "q", True, ["c"])
    result = rag_eval.QuestionResult(question, ["a", "b", "c"], 0.5, 0.5, False, True)

    assert result.reciprocal_rank == pytest.approx(1 / 3)
    assert result.hit_at(3) is True
    assert result.hit_at(2) is False


def test_abstention_metrics():
    abstained = [True, True, False, True]
    answerable = [False, True, True, False]

    metrics = rag_eval.abstention_metrics(abstained, answerable)

    assert metrics["precision"] == pytest.approx(2 / 3)
    assert metrics["recall"] == 1.0
    assert metrics["wrongly_abstained"] == 1


def test_check_ollama_reports_an_unreachable_server():
    ok, reason = rag_eval.check_ollama("http://127.0.0.1:9", "llama3.1:8b")
    assert ok is False
    assert "not reachable" in reason


def test_question_groups_follow_the_id_prefix():
    assert rag_eval.EvalQuestion("inc-01", "q", True, ["x"]).group == "incident history"
    assert rag_eval.EvalQuestion("pb-01", "q", True, ["x"]).group == "playbooks"
    assert rag_eval.EvalQuestion("off-01", "q", False, []).group == "unanswerable"


# --- report -----------------------------------------------------------------------


def test_limitations_cover_the_four_required_topics():
    baseline = detector.BaselineData(
        "synthetic", "synthetic", "kbd", np.zeros((10, 17)), list(FEATURE_NAMES), None
    )
    text = report.limitations({}, baseline)

    assert "Slowed and randomized injection" in text
    assert "Raw Input is observe-only" in text
    assert "baseline is small" in text
    assert "Digispark bootloader" in text
    assert EM_DASH not in text


def test_limitations_flag_an_over_abstaining_gate():
    baseline = detector.synthetic_baseline()
    facts = {
        "rag_retrieval_gate": {"answerable": 30, "wrongly_abstained": 20},
        "llm_available": False,
    }

    text = report.limitations(facts, baseline)

    assert "refuses too often" in text
    assert "20 of 30" in text


# --- evaluate_all -------------------------------------------------------------------


def test_evaluate_all_writes_the_document(tmp_path, monkeypatch):
    monkeypatch.setattr(detector, "FP_SYNTHETIC_STREAMS", 2)
    monkeypatch.setattr(detector, "FP_SYNTHETIC_PRESSES", 120)
    output = tmp_path / "docs" / "EVALUATION.md"

    status = evaluate_all.main(
        [
            "--user", "nobody-with-a-baseline",
            "--seeds", "1",
            "--skip-rag",
            "--skip-e2e",
            "--output", str(output),
            "--hardware-csv", str(tmp_path / "none.csv"),
        ]
    )

    assert status == 0
    text = output.read_text(encoding="utf-8")
    for heading in ("## 1. HID Firewall", "## 2. IncidentRAG", "## 3. End to end",
                    "## 4. Limitations"):
        assert heading in text
    assert "Detector baseline: synthetic" in text
    assert "Not run (skipped on the command line)" in text
    assert (tmp_path / "docs" / "figures" / "detector_roc.png").exists()
    assert EM_DASH not in text


def test_a_crashing_section_is_reported_and_fails_the_run(tmp_path, monkeypatch):
    def boom(*args, **kwargs):
        raise RuntimeError("simulated failure")

    monkeypatch.setattr(detector, "ablation_section", boom)
    monkeypatch.setattr(detector, "FP_SYNTHETIC_STREAMS", 1)
    monkeypatch.setattr(detector, "FP_SYNTHETIC_PRESSES", 60)
    output = tmp_path / "EVALUATION.md"

    status = evaluate_all.main(
        ["--seeds", "1", "--skip-rag", "--skip-e2e", "--output", str(output),
         "--hardware-csv", str(tmp_path / "none.csv"), "--user", "nobody"]
    )

    assert status == 1
    assert "This section failed" in output.read_text(encoding="utf-8")

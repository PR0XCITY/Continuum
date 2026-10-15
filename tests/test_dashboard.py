"""Tests for the dashboard's pure helpers, HTML builders and API client.

No Streamlit session is needed: everything here is plain functions, and
the client is exercised against httpx.MockTransport.
"""

from __future__ import annotations

from datetime import UTC, date, datetime, timedelta

import httpx
import pytest

from continuum.common.schemas import TRIAL_MS_TO_BLOCK, TRIAL_MS_TO_LOCK, TRIAL_PRESSES_TO_BLOCK
from continuum.dashboard import helpers, style
from continuum.dashboard.api import ApiError, ConnectorClient

NOW = datetime(2026, 10, 1, 12, 0, 0, tzinfo=UTC)


def _incident(**overrides):
    base = {
        "incident_id": "11111111-2222-3333-4444-555555555555",
        "detected_at": "2026-09-30T08:15:00+00:00",
        "device": {"device_id": r"HID\VID_16C0&PID_27DB\1", "name": "Digispark Keyboard"},
        "verdict": "blocked",
        "attack_pattern": "burst_injection",
        "anomaly_score": 0.31234,
        "action_taken": "locked_and_disabled",
        "time_to_detect_ms": 12,
        "notes": "",
        "features_summary": {},
    }
    base.update(overrides)
    return base


# --- formatting ---------------------------------------------------------------------


@pytest.mark.parametrize(
    ("delta", "expected"),
    [
        (timedelta(seconds=12), "12 s ago"),
        (timedelta(minutes=4), "4 min ago"),
        (timedelta(hours=3), "3 h ago"),
        (timedelta(days=1), "1 day ago"),
        (timedelta(days=6), "6 days ago"),
    ],
)
def test_format_relative_age(delta, expected):
    assert helpers.format_relative_age((NOW - delta).isoformat(), now=NOW) == expected


def test_format_relative_age_of_nothing():
    assert helpers.format_relative_age(None, now=NOW) == "never"


def test_mode_label_and_device_verdict():
    assert helpers.mode_label("lock_and_disable") == "Lock and disable"
    assert helpers.mode_label(None) == "unknown"
    assert helpers.device_verdict("normal", disabled=True) == "blocked"
    assert helpers.device_verdict(None, disabled=False) == "idle"


# --- live status --------------------------------------------------------------------


def test_merge_devices_joins_runtime_devices_with_live_snapshots():
    runtime_devices = [
        {"device_id": "a", "name": "Office Keyboard", "vendor_id": "046D", "product_id": "C31C",
         "bus_type": "USB", "disabled": False},
        {"device_id": "b", "name": "Digispark", "vendor_id": "16C0", "product_id": "27DB",
         "bus_type": "USB", "disabled": True},
    ]
    snapshots = [
        {"device_id": "a", "verdict": "suspicious", "anomaly_score": 0.2, "threshold": 0.1,
         "updated_at": NOW.isoformat()},
        {"device_id": "gone", "verdict": "normal", "anomaly_score": 0.0, "threshold": 0.1,
         "updated_at": NOW.isoformat()},
    ]

    rows = helpers.merge_devices(runtime_devices, snapshots)

    assert [r["device_id"] for r in rows] == ["b", "a", "gone"]
    assert rows[0]["badge"] == "blocked"
    assert rows[1]["badge"] == "suspicious"
    assert rows[2]["attached"] is False


def test_update_interval_history_dedupes_and_keeps_only_the_last_minute():
    old = {"device_id": "a", "updated_at": (NOW - timedelta(seconds=90)).isoformat(),
           "features": {"flight_mean_ms": 140.0}, "verdict": "normal"}
    recent = {"device_id": "a", "updated_at": (NOW - timedelta(seconds=5)).isoformat(),
              "features": {"flight_mean_ms": 120.0}, "verdict": "normal"}

    history = helpers.update_interval_history([], [old, recent], now=NOW)
    history = helpers.update_interval_history(history, [recent], now=NOW)

    assert len(history) == 1
    assert history[0]["interval_ms"] == 120.0


# --- incidents ----------------------------------------------------------------------


def test_build_incident_params_makes_the_end_date_inclusive():
    params = helpers.build_incident_params(
        start=date(2026, 9, 1), end=date(2026, 9, 30), verdict="blocked",
        attack_pattern=None, device_id="  dev  ",
    )

    assert params["start_time"].startswith("2026-09-01T00:00:00")
    assert params["end_time"].startswith("2026-09-30T23:59:59")
    assert params["verdict"] == "blocked"
    assert params["device_id"] == "dev"
    assert "attack_pattern" not in params


def test_filter_by_text_searches_names_ids_and_notes():
    items = [_incident(notes="found at the library kiosk"), _incident(incident_id="other")]

    assert len(helpers.filter_by_text(items, "KIOSK")) == 1
    assert len(helpers.filter_by_text(items, "digispark")) == 2
    assert len(helpers.filter_by_text(items, "  ")) == 2


def test_incidents_frame_and_daily_counts():
    items = [
        _incident(detected_at="2026-09-28T10:00:00+00:00"),
        _incident(detected_at="2026-09-30T10:00:00+00:00", verdict="suspicious"),
    ]

    frame = helpers.incidents_frame(items)
    counts = helpers.daily_counts(items)

    assert list(frame["attack_pattern"]) == ["Burst injection", "Burst injection"]
    assert frame["anomaly_score"].iloc[0] == 0.312
    # Three days (one empty) times two verdicts.
    assert len(counts) == 6
    assert counts["count"].sum() == 2


def test_detection_timing_rows_prefer_first_keystroke_figures():
    with_timings = _incident(
        features_summary={TRIAL_PRESSES_TO_BLOCK: 40.0, TRIAL_MS_TO_BLOCK: 212.4,
                          TRIAL_MS_TO_LOCK: 230.9}
    )

    rows = dict(helpers.detection_timing_rows(with_timings))

    assert rows["First keystroke to block"] == "212 ms, 40 key presses"
    assert rows["First keystroke to lock"] == "231 ms"
    assert rows["Suspicious to blocked"] == "12 ms"
    assert list(dict(helpers.detection_timing_rows(_incident()))) == ["Suspicious to blocked"]


def test_question_about_incident_names_it_unambiguously():
    question = helpers.question_about_incident(_incident())

    assert "11111111-2222-3333-4444-555555555555" in question
    assert "Digispark Keyboard" in question
    assert "burst injection" in question


# --- settings and calibration -------------------------------------------------------


def test_parse_allowlist_text_drops_blanks_and_duplicates():
    assert helpers.parse_allowlist_text("a\n\n b \na\n") == ["a", "b"]


def test_parse_markdown_tables_and_prose():
    markdown = (
        "# Title\n\nModel: x\nThreshold: 0.1\n\n| a | b |\n| --- | --- |\n| 1 | 2 |\n\n"
        "![plot](x.png)\n\nClosing paragraph.\n"
    )

    [table] = helpers.parse_markdown_tables(markdown)

    assert list(table.columns) == ["a", "b"]
    assert table.iloc[0].tolist() == ["1", "2"]
    assert helpers.markdown_prose(markdown) == ["Model: x\nThreshold: 0.1", "Closing paragraph."]


def test_plain_label_strips_markdown():
    assert helpers.plain_label("[x](http://e) **bold**") == "x http://e bold"


def test_sensitivity_description():
    assert helpers.sensitivity_description(5) == "Calibrated default"
    assert "More alerts" in helpers.sensitivity_description(9)


# --- style: untrusted text is always escaped ----------------------------------------


def test_builders_escape_untrusted_text():
    hostile = '<img src="http://evil/pixel.png"><script>x()</script>'

    for markup in (
        style.text_block(hostile),
        style.badge(hostile),
        style.stat_card(hostile, hostile, hostile),
        style.card(style.text_block(hostile), title=hostile, eyebrow=hostile),
        style.key_values([(hostile, hostile)]),
    ):
        assert "<img" not in markup
        assert "<script" not in markup


def test_confidence_meter_clamps_and_marks_the_threshold():
    markup = style.confidence_meter(1.7, 0.5)
    assert "width:100.0%" in markup
    assert "left:50.0%" in markup


# --- API client ---------------------------------------------------------------------


def _client(handler) -> ConnectorClient:
    return ConnectorClient("http://test", "token", transport=httpx.MockTransport(handler))


def test_client_sends_the_bearer_token_and_encodes_device_ids():
    seen = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(200, json={"status": "queued"})

    _client(handler).unblock(r"HID\VID_16C0&PID_27DB\1")

    assert seen[0].headers["Authorization"] == "Bearer token"
    assert seen[0].url.raw_path == b"/devices/HID%5CVID_16C0%26PID_27DB%5C1/unblock"


@pytest.mark.parametrize(
    ("status", "fragment"),
    [(401, "rejected the API token"), (429, "rate limiting"), (500, "HTTP 500")],
)
def test_client_turns_http_errors_into_readable_messages(status, fragment):
    client = _client(lambda request: httpx.Response(status, json={"detail": "boom"}))

    with pytest.raises(ApiError, match=fragment):
        client.stats()


def test_client_reports_an_unreachable_connector():
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("refused")

    with pytest.raises(ApiError, match="Cannot reach the connector"):
        _client(handler).health()


def test_llm_disclosure_says_where_answers_are_written():
    class _Rag:
        groq_model = "llama-3.1-8b-instant"
        ollama_model = "llama3.1:8b"

    groq = helpers.llm_disclosure("groq", _Rag())
    local = helpers.llm_disclosure("ollama", _Rag())

    assert "Groq's cloud API" in groq and "sent to Groq" in groq
    assert "llama-3.1-8b-instant" in groq
    assert "locally in Ollama" in local and "nothing leaves this machine" in local


# --- Train page ----------------------------------------------------------------


def test_typing_passages_take_each_playbooks_when_to_use_section(tmp_path):
    (tmp_path / "a.md").write_text(
        "# A\n\n## When to use\n\nUse **this** when\nthe `thing` happens.\n\n## Steps\n\n1. x\n",
        encoding="utf-8",
    )
    (tmp_path / "b.md").write_text("# B\n\nNo such section.\n", encoding="utf-8")

    assert helpers.typing_passages(tmp_path) == ["Use this when the thing happens."]


def test_the_real_corpus_gives_a_passage_per_playbook():
    from pathlib import Path

    corpus = Path(__file__).resolve().parents[1] / "data" / "corpus"
    passages = helpers.typing_passages(corpus)

    assert len(passages) == len(list(corpus.rglob("*.md")))
    assert all(len(p.split()) >= 40 for p in passages)


def test_passage_for_session_cycles_through_passages():
    passages = ["one", "two", "three"]

    assert helpers.passage_for_session(passages, 0) == (0, "one")
    assert helpers.passage_for_session(passages, 4) == (1, "two")
    assert helpers.passage_for_session([], 2) == (0, "")


def test_baseline_progress_wording():
    assert "60 more windows needed" in helpers.baseline_progress(0, 60, 150)
    assert "Enough to train" in helpers.baseline_progress(90, 60, 150)
    assert "Train the model" in helpers.baseline_progress(150, 60, 150)


def test_typing_box_escapes_the_passage_and_has_no_network_code():
    markup = style.typing_box('<img src="http://evil/x.png"> type this')

    assert "<img" not in markup
    assert "&lt;img" in markup
    for network_call in ("fetch(", "XMLHttpRequest", "sendBeacon", "WebSocket", "postMessage"):
        assert network_call not in markup

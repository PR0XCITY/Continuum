"""Continuum dashboard: the operator console for the HID Firewall.

Responsibility: a Streamlit app with five pages (live status, incidents,
Ask IncidentRAG, calibration and model, settings). It talks to the
connector API only, with the bearer token from .env; it never opens the
database, the vector store or the capture layer. Run it with
`just run-dashboard` (or `.\\tasks.ps1 run-dashboard`) from the repo
root, so .streamlit/config.toml applies its theme and turns off
Streamlit's usage statistics.

Styling is custom CSS in dashboard/style.py. Untrusted text (incident notes, device names, model
answers, retrieved snippets) is rendered only through style.py's
escaping builders or Streamlit's own escaped widgets, never through
st.markdown.
"""

from __future__ import annotations

import os
from datetime import UTC, date, datetime, timedelta
from typing import Any

import altair as alt
import pandas as pd
import streamlit as st
import streamlit.components.v1 as components

from continuum.common.config import get_settings
from continuum.dashboard import helpers, style
from continuum.dashboard.api import ApiError, ConnectorClient
from continuum.detection.scorer import (
    DEFAULT_SENSITIVITY,
    MAX_SENSITIVITY,
    MIN_SENSITIVITY,
    threshold_offset_for_sensitivity,
)
from continuum.rag.ingest import resolve_corpus_path

PAGE_LIVE = "Live status"
PAGE_INCIDENTS = "Incidents"
PAGE_ASK = "Ask IncidentRAG"
PAGE_CALIBRATION = "Calibration and model"
PAGE_SETTINGS = "Settings"
PAGE_TRAIN = "Train"
PAGES = (PAGE_LIVE, PAGE_INCIDENTS, PAGE_ASK, PAGE_TRAIN, PAGE_CALIBRATION, PAGE_SETTINGS)

LIVE_REFRESH_SECONDS = 2
DEFAULT_INCIDENT_WINDOW_DAYS = 90

VERDICT_FILTERS = ("All verdicts", "blocked", "suspicious", "normal")
CHART_VERDICT_COLOURS = {
    "blocked": style.PASTELS["red"][1],
    "suspicious": style.PASTELS["yellow"][1],
    "normal": style.PASTELS["green"][1],
}


# --- setup -------------------------------------------------------------------


@st.cache_resource
def _client(base_url: str, token: str) -> ConnectorClient:
    return ConnectorClient(base_url, token)


def _html(markup: str) -> None:
    st.markdown(markup, unsafe_allow_html=True)


def _page_header(title: str, lede: str) -> None:
    st.title(title)
    _html(f'<div class="ct-lede">{style.escape(lede)}</div>')


def _error_card(error: Exception) -> None:
    _html(style.card(style.text_block(str(error)), title="Could not load this page", amber=True))


def _chart(chart: alt.Chart) -> None:
    font = "Segoe UI, Helvetica Neue, sans-serif"
    themed = (
        chart.configure_axis(
            labelFont=font,
            titleFont=font,
            labelColor=style.MUTED,
            titleColor=style.MUTED,
            gridColor=style.HAIRLINE,
            domainColor=style.HAIRLINE,
            tickColor=style.HAIRLINE,
        )
        .configure_legend(labelFont=font, titleFont=font, labelColor=style.TEXT, orient="bottom")
        .configure_view(strokeWidth=0)
    )
    st.altair_chart(themed, use_container_width=True, theme=None)


def _ask_about(question: str) -> None:
    # Runs as a widget callback, before the next script run, which is the
    # one moment Streamlit allows widget-bound session state to change.
    st.session_state["page"] = PAGE_ASK
    st.session_state["rag_question"] = question


# --- cached reads ------------------------------------------------------------


@st.cache_data(ttl=10, show_spinner=False)
def _incidents(_client: ConnectorClient, params: tuple[tuple[str, Any], ...]) -> dict:
    return _client.incidents(dict(params))


@st.cache_data(ttl=10, show_spinner=False)
def _stats(_client: ConnectorClient) -> dict:
    return _client.stats()


@st.cache_data(ttl=60, show_spinner=False)
def _calibration(_client: ConnectorClient) -> dict:
    return _client.calibration()


@st.cache_data(ttl=3, show_spinner=False)
def _runtime(_client: ConnectorClient) -> dict:
    return _client.runtime()


# --- sidebar -----------------------------------------------------------------


def _sidebar(client: ConnectorClient) -> str:
    with st.sidebar:
        _html(
            '<div style="padding:8px 0 20px">'
            f'<div style="font-family:{style.SERIF};font-size:1.6rem;color:{style.INK};'
            'letter-spacing:-0.02em">Continuum</div>'
            '<div class="ct-hint">HID Firewall console</div></div>'
        )
        st.session_state.setdefault("page", PAGES[0])
        page = st.radio("Navigate", PAGES, key="page", label_visibility="collapsed")

        st.divider()
        try:
            runtime = _runtime(client)
            connector_line = f"{style.status_dot(True)}Connector reachable"
            if runtime["running"]:
                runtime_line = f"{style.status_dot(True)}Runtime running"
            else:
                runtime_line = f"{style.status_dot(False)}Runtime not running"
        except ApiError as error:
            problem = {
                401: "Connector rejected the API token",
                429: "Connector busy (rate limited)",
            }.get(error.status_code, "Connector unreachable")
            connector_line = f"{style.status_dot(False)}{problem}"
            runtime_line = f"{style.status_dot(False)}Runtime status unknown"
        _html(
            f'<div class="ct-hint" style="line-height:2">{connector_line}<br>{runtime_line}</div>'
            f'<div class="ct-hint ct-mono" style="margin-top:12px">{style.escape(client.base_url)}'
            "</div>"
        )
    return page


# --- page 1: live status -------------------------------------------------------


def _unblock_button(
    target: Any, client: ConnectorClient, device: dict[str, Any], *, runtime_running: bool
) -> None:
    """An Unblock button under a blocked device's card on the Live status page."""
    if target.button(
        "Unblock device",
        key=f"live_unblock_{device['device_id']}",
        type="primary",
        use_container_width=True,
        help="Only once the device has been examined and is known to be safe.",
    ):
        try:
            client.unblock(device["device_id"])
        except ApiError as error:
            target.error(str(error))
        else:
            target.success(
                "Unblock queued. The runtime applies it within a second."
                if runtime_running
                else "Unblock queued. The runtime is not running, so it applies when it starts."
            )


@st.fragment(run_every=LIVE_REFRESH_SECONDS)
def _live_panel(client: ConnectorClient) -> None:
    now = datetime.now(UTC)
    if st.session_state.get("live_auto", True) or "live_data" not in st.session_state:
        try:
            st.session_state["live_data"] = (client.runtime(), client.live())
        except ApiError as error:
            _error_card(error)
            return
    runtime, snapshots = st.session_state["live_data"]

    history = helpers.update_interval_history(
        st.session_state.get("interval_history", []), snapshots, now=now
    )
    st.session_state["interval_history"] = history

    columns = st.columns(4)
    if runtime["state"] == "never_started":
        state_value, state_hint = "Never started", "No heartbeat recorded yet"
    else:
        state_value = "Running" if runtime["running"] else "Stopped"
        state_hint = "Last heartbeat " + helpers.format_relative_age(
            runtime["last_heartbeat"], now=now
        )
    columns[0].markdown(style.stat_card("Runtime", state_value, state_hint), unsafe_allow_html=True)

    elevated = runtime.get("elevated")
    columns[1].markdown(
        style.stat_card(
            "Elevated",
            "unknown" if elevated is None else ("Yes" if elevated else "No"),
            "Needed to disable devices" if elevated is False else "",
        ),
        unsafe_allow_html=True,
    )

    mode_hint_parts = []
    if runtime.get("configured_mode") and runtime["configured_mode"] != runtime.get(
        "effective_mode"
    ):
        mode_hint_parts.append(f"configured: {helpers.mode_label(runtime['configured_mode'])}")
    if runtime.get("dry_run"):
        mode_hint_parts.append("dry run, no real actions")
    columns[2].markdown(
        style.stat_card(
            "Response mode",
            helpers.mode_label(runtime.get("effective_mode")),
            ", ".join(mode_hint_parts),
        ),
        unsafe_allow_html=True,
    )

    threshold = runtime.get("threshold")
    if runtime.get("model_version") == "none":
        threshold_value, threshold_hint = "not trained", "Record your typing on the Train page"
    else:
        threshold_value = "unknown" if threshold is None else f"{threshold:.4f}"
        sensitivity = runtime.get("sensitivity")
        threshold_hint = f"sensitivity {sensitivity}" if sensitivity else ""
    columns[3].markdown(
        style.stat_card("Threshold", threshold_value, threshold_hint),
        unsafe_allow_html=True,
    )

    st.subheader("Keyboards")
    devices = helpers.merge_devices(runtime.get("devices") or [], snapshots)
    if not devices:
        _html(
            style.card(
                style.text_block(
                    "No keyboards reported yet. Start everything with .\\tasks.ps1 run-all "
                    "and approve the administrator prompt; attached keyboards appear here "
                    "within seconds."
                )
            )
        )
    else:
        device_columns = st.columns(3)
        for index, device in enumerate(devices):
            score = device.get("anomaly_score")
            limit = device.get("threshold")
            score_text = (
                f"score {score:.3f} against {limit:.3f}"
                if score is not None and limit is not None
                else "no window scored yet"
            )
            notes = []
            if device["disabled"]:
                notes.append(helpers.blocked_note(device))
            if not device["attached"]:
                notes.append("no longer attached")
            body = (
                f'<div class="ct-row"><div class="ct-card-title">{style.escape(device["name"])}'
                f"</div>{style.verdict_badge(device['badge'])}</div>"
                f'<div class="ct-hint ct-mono">{style.escape(device["vendor_product"])} '
                f'{style.escape(device["bus_type"])}</div>'
                f'<div class="ct-hint">{style.escape(score_text)}</div>'
                f'<div class="ct-hint">last window '
                f'{style.escape(helpers.format_relative_age(device.get("updated_at"), now=now))}'
                f'{style.escape(", " + ", ".join(notes) if notes else "")}</div>'
            )
            column = device_columns[index % 3]
            column.markdown(style.card(body), unsafe_allow_html=True)
            if device["disabled"]:
                _unblock_button(
                    column, client, device, runtime_running=bool(runtime["running"])
                )

    st.subheader("Inter-key interval, last 60 seconds")
    if not history:
        st.caption(
            "No windows scored in the last 60 seconds. A point appears each time the runtime "
            "scores a window of typing on a keyboard."
        )
        return
    names = {device["device_id"]: device["name"] for device in devices}
    frame = pd.DataFrame(history)
    frame["device"] = [helpers.short_device_label(d, names) for d in frame["device_id"]]
    chart = (
        alt.Chart(frame)
        .mark_line(point=alt.OverlayMarkDef(size=28), strokeWidth=1.6)
        .encode(
            x=alt.X(
                "time:T",
                title=None,
                scale=alt.Scale(domain=[now - timedelta(seconds=60), now]),
                axis=alt.Axis(format="%H:%M:%S"),
            ),
            y=alt.Y("interval_ms:Q", title="mean inter-key interval (ms)"),
            color=alt.Color("device:N", title=None, scale=alt.Scale(range=style.CHART_PALETTE)),
            tooltip=[
                "device:N",
                alt.Tooltip("interval_ms:Q", format=".1f"),
                "verdict:N",
                alt.Tooltip("time:T", format="%H:%M:%S"),
            ],
        )
        .properties(height=260)
    )
    _chart(chart)
    st.caption(
        "Sampled from /live every 2 seconds; /live keeps only each device's latest window, "
        "so windows scored between two polls are not shown."
    )


def page_live(client: ConnectorClient) -> None:
    _page_header(
        "Live status",
        "What the HID Firewall is doing right now: runtime health, attached keyboards and "
        "their latest verdicts, and typing cadence over the last minute.",
    )
    st.toggle(f"Refresh every {LIVE_REFRESH_SECONDS} seconds", value=True, key="live_auto")
    _live_panel(client)


# --- page 2: incidents ---------------------------------------------------------


def _incident_detail(client: ConnectorClient, incident: dict, runtime_running: bool) -> None:
    device = incident["device"]
    pattern = helpers.ATTACK_PATTERN_LABELS.get(
        incident["attack_pattern"], incident["attack_pattern"]
    )
    followups = ", ".join(f.replace("_", " ") for f in incident["recommended_followups"])
    body = (
        f'<div class="ct-row"><div class="ct-card-title">{style.escape(device["name"])}</div>'
        f'<div>{style.verdict_badge(incident["verdict"])} {style.badge(pattern, "blue")}</div>'
        "</div><div style='height:12px'></div>"
        + style.key_values(
            [
                ("Incident", incident["incident_id"]),
                ("Detected", helpers.format_timestamp(incident["detected_at"])),
                ("Device id", device["device_id"]),
                ("Vendor and product", f"{device['vendor_id']}:{device['product_id']}"),
                (
                    "Anomaly score",
                    f"{incident['anomaly_score']:.3f} against threshold "
                    f"{incident['threshold']:.3f}",
                ),
                ("Action taken", incident["action_taken"].replace("_", " ")),
                *helpers.detection_timing_rows(incident),
                ("MITRE ATT&CK", incident["mitre_technique"]),
                ("Recommended follow-ups", followups or "none"),
            ]
        )
    )
    if incident.get("notes"):
        body += (
            "<div style='height:16px'></div><div class='ct-eyebrow'>Notes</div>"
            + style.text_block(incident["notes"])
        )
    _html(style.card(body, eyebrow="Selected incident"))

    left, right, _ = st.columns([1, 1, 2])
    left.button(
        "Ask IncidentRAG about this",
        type="primary",
        key=f"ask_{incident['incident_id']}",
        on_click=_ask_about,
        args=(helpers.question_about_incident(incident),),
        use_container_width=True,
    )
    with right.popover("Unblock device", use_container_width=True):
        st.write(
            "Lift the block on this device now instead of waiting for the automatic release. "
            "Only do this once the device has been examined and is known to be safe."
        )
        if not runtime_running:
            st.caption("The runtime is not running, so the command waits until it starts.")
        if st.button("Confirm unblock", type="primary", key=f"unblock_{incident['incident_id']}"):
            try:
                client.unblock(device["device_id"])
            except ApiError as error:
                st.error(str(error))
            else:
                st.success("Unblock queued. The runtime applies it within a few seconds.")

    if incident.get("features_summary"):
        with st.expander("Cadence features at detection"):
            st.dataframe(
                pd.DataFrame(
                    sorted(incident["features_summary"].items()), columns=["feature", "value"]
                ),
                hide_index=True,
                use_container_width=True,
            )


def page_incidents(client: ConnectorClient) -> None:
    _page_header(
        "Incidents",
        "Every blocked or suspicious device, as recorded by the connector. Select a row for "
        "details, to unblock the device, or to ask IncidentRAG about it.",
    )
    stats = _stats(client)
    columns = st.columns(3)
    columns[0].markdown(
        style.stat_card("Incidents recorded", str(stats["total_incidents"])),
        unsafe_allow_html=True,
    )
    mean_score = stats.get("mean_anomaly_score")
    columns[1].markdown(
        style.stat_card(
            "Mean anomaly score", "none" if mean_score is None else f"{mean_score:.3f}"
        ),
        unsafe_allow_html=True,
    )
    mean_ttd = stats.get("mean_time_to_detect_ms")
    columns[2].markdown(
        style.stat_card(
            "Mean time to detect", "none" if mean_ttd is None else f"{mean_ttd:.0f} ms"
        ),
        unsafe_allow_html=True,
    )

    today = datetime.now(UTC).date()
    filter_columns = st.columns([2, 1.2, 1.4, 2])
    picked = filter_columns[0].date_input(
        "Detected between",
        value=(today - timedelta(days=DEFAULT_INCIDENT_WINDOW_DAYS), today),
        max_value=today,
    )
    start, end = (picked + (None, None))[:2] if isinstance(picked, tuple) else (picked, None)
    verdict = filter_columns[1].selectbox("Verdict", VERDICT_FILTERS)
    pattern = filter_columns[2].selectbox(
        "Attack pattern",
        ("All patterns", *helpers.ATTACK_PATTERN_LABELS),
        format_func=lambda key: helpers.ATTACK_PATTERN_LABELS.get(key, key),
    )
    search = filter_columns[3].text_input(
        "Search", placeholder="device name, device id, notes or incident id"
    )

    params = helpers.build_incident_params(
        start=start if isinstance(start, date) else None,
        end=end if isinstance(end, date) else None,
        verdict=None if verdict == VERDICT_FILTERS[0] else verdict,
        attack_pattern=None if pattern == "All patterns" else pattern,
        device_id=None,
    )
    listing = _incidents(client, tuple(sorted(params.items())))
    items = helpers.filter_by_text(listing["items"], search)

    st.subheader("Incidents per day")
    timeline = helpers.daily_counts(
        items,
        start=start if isinstance(start, date) else None,
        end=end if isinstance(end, date) else None,
    )
    if timeline.empty:
        st.caption("No incidents in this range.")
    else:
        verdicts = sorted(timeline["verdict"].unique())
        chart = (
            alt.Chart(timeline)
            .mark_bar(size=6, cornerRadiusTopLeft=2, cornerRadiusTopRight=2)
            .encode(
                x=alt.X("day:T", title=None, axis=alt.Axis(format="%d %b")),
                y=alt.Y("count:Q", title="incidents", axis=alt.Axis(tickMinStep=1)),
                color=alt.Color(
                    "verdict:N",
                    title=None,
                    scale=alt.Scale(
                        domain=verdicts,
                        range=[CHART_VERDICT_COLOURS.get(v, style.MUTED) for v in verdicts],
                    ),
                ),
                tooltip=[alt.Tooltip("day:T", format="%Y-%m-%d"), "verdict:N", "count:Q"],
            )
            .properties(height=200)
        )
        _chart(chart)
    if listing["total"] > len(listing["items"]):
        st.caption(
            f"Showing the most recent {len(listing['items'])} of {listing['total']} matching "
            "incidents."
        )

    st.subheader(f"{len(items)} incidents")
    if not items:
        st.caption("Nothing matches these filters.")
        return
    frame = helpers.incidents_frame(items)
    selection = st.dataframe(
        frame,
        hide_index=True,
        use_container_width=True,
        on_select="rerun",
        selection_mode="single-row",
        key="incident_table",
        height=360,
        column_order=[
            "detected_at",
            "device",
            "verdict",
            "attack_pattern",
            "anomaly_score",
            "action_taken",
            "time_to_detect_ms",
            "has_notes",
        ],
        column_config={
            "detected_at": st.column_config.DatetimeColumn(
                "Detected (UTC)", format="YYYY-MM-DD HH:mm"
            ),
            "device": "Device",
            "verdict": "Verdict",
            "attack_pattern": "Pattern",
            "anomaly_score": st.column_config.NumberColumn("Score", format="%.3f"),
            "action_taken": "Action",
            "time_to_detect_ms": st.column_config.NumberColumn("Detect (ms)"),
            "has_notes": st.column_config.CheckboxColumn("Notes"),
        },
    )
    rows = selection.selection.rows if selection else []
    selected = items[rows[0]] if rows else items[0]
    if not rows:
        st.caption("Showing the newest incident. Select a row to see another one.")
    _incident_detail(client, selected, runtime_running=_runtime(client)["running"])


# --- page 3: ask IncidentRAG ------------------------------------------------------


def _render_rag_exchange(exchange: dict, threshold: float) -> None:
    response = exchange["response"]
    _html(
        style.card(style.text_block(exchange["question"]), eyebrow="You asked")
    )
    meter = style.confidence_meter(response["confidence"], threshold)
    if response["abstained"]:
        sources = response["citations"]
        source_list = "".join(
            f"<li>{style.escape(c['title'])} "
            f'<span class="ct-mono ct-hint">{style.escape(c["doc_id"])}, '
            f"similarity {c['score']:.2f}</span></li>"
            for c in sources
        )
        body = (
            style.text_block(response["message"] or "Not enough evidence to answer reliably.")
            + meter
            + (
                "<div style='height:12px'></div><div class='ct-eyebrow'>Nearest sources to "
                f"read yourself</div><ul>{source_list}</ul>"
                if sources
                else "<div class='ct-hint'>No related sources were found.</div>"
            )
        )
        _html(style.card(body, title="Insufficient evidence", eyebrow="IncidentRAG", amber=True))
        return

    _html(
        style.card(
            style.text_block(response["answer"] or "")
            + meter
            + (
                f'<div class="ct-hint">Generated by {style.escape(response["generated_by"])}'
                "</div>"
                if response.get("generated_by")
                else ""
            ),
            eyebrow="IncidentRAG",
        )
    )
    for number, citation in enumerate(response["citations"], start=1):
        label = helpers.plain_label(citation["title"])
        with st.expander(f"Source {number}: {label}, similarity {citation['score']:.2f}"):
            _html(
                f'<div class="ct-hint ct-mono">{style.escape(citation["doc_id"])}</div>'
                + style.text_block(citation["snippet"])
            )


def page_ask(client: ConnectorClient) -> None:
    _page_header(
        "Ask IncidentRAG",
        "Answers come only from recorded incidents and the playbooks in data/corpus, with "
        "numbered citations. When the evidence is weak, IncidentRAG says so instead of "
        "guessing.",
    )
    rag_settings = get_settings().rag
    threshold = rag_settings.confidence_threshold
    st.caption(helpers.llm_disclosure(rag_settings.llm_provider, rag_settings))
    st.session_state.setdefault("rag_question", "")
    st.session_state.setdefault("rag_history", [])

    with st.form("ask_form", border=False):
        question = st.text_area(
            "Question",
            key="rag_question",
            height=100,
            placeholder="For example: What should I do after a burst injection was blocked?",
        )
        submitted = st.form_submit_button("Ask", type="primary")

    if submitted and question.strip():
        with st.spinner("Searching incidents and playbooks"):
            try:
                response = client.query(question.strip())
            except ApiError as error:
                _error_card(error)
                response = None
        if response is not None:
            st.session_state["rag_history"].insert(
                0, {"question": question.strip(), "response": response}
            )

    history = st.session_state["rag_history"]
    if not history:
        st.caption(
            "Tip: on the Incidents page, \"Ask IncidentRAG about this\" fills in a question "
            "about the selected incident."
        )
        return
    for exchange in history:
        _render_rag_exchange(exchange, threshold)
    if st.button("Clear conversation"):
        st.session_state["rag_history"] = []
        st.rerun()


# --- page 4: calibration and model ------------------------------------------------


def page_calibration(client: ConnectorClient) -> None:
    _page_header(
        "Calibration and model",
        "The typing baseline the detector was trained on, the model and threshold in use, "
        "and how that model performed against simulated attacks.",
    )
    data = _calibration(client)
    runtime = _runtime(client)
    now = datetime.now(UTC)

    models = [m for m in data["models"] if "error" not in m]
    active = next((m for m in models if m["version"] == runtime.get("model_version")), None)
    if active is None and models:
        active = max(models, key=lambda m: m["modified_at"])
    baselines = [b for b in data["baselines"] if "error" not in b]
    baseline = None
    if active is not None:
        baseline = next((b for b in baselines if b["user"] == active["user"]), None)
    if baseline is None and baselines:
        baseline = max(baselines, key=lambda b: b["modified_at"])

    columns = st.columns(4)
    columns[0].markdown(
        style.stat_card(
            "Baseline age",
            helpers.format_relative_age(baseline["last_captured_at"], now=now)
            if baseline
            else "no baseline",
            f"user {baseline['user']}" if baseline else "Record one with tools/record_baseline.py",
        ),
        unsafe_allow_html=True,
    )
    columns[1].markdown(
        style.stat_card(
            "Baseline windows",
            str(baseline["n_windows"]) if baseline else "0",
            f"device {baseline['device_id']}" if baseline else "",
        ),
        unsafe_allow_html=True,
    )
    if runtime["running"] and runtime.get("threshold") is not None:
        threshold_value = f"{runtime['threshold']:.4f}"
        threshold_hint = f"in use by the runtime, sensitivity {runtime['sensitivity']}"
    elif active is not None:
        threshold_value = f"{active['threshold_at_configured_sensitivity']:.4f}"
        threshold_hint = (
            f"calibrated {active['calibrated_threshold']:.4f}, "
            f"sensitivity {data['configured_sensitivity']}"
        )
    else:
        threshold_value, threshold_hint = "none", "No trained model"
    columns[2].markdown(
        style.stat_card("Current threshold", threshold_value, threshold_hint),
        unsafe_allow_html=True,
    )
    columns[3].markdown(
        style.stat_card(
            "Model version",
            active["version"] if active else "none",
            (
                f"{active['model_type'].replace('_', ' ')}, target false positive rate "
                f"{active['target_false_positive_rate']:.1%}"
            )
            if active
            else "Train one with tools/train_model.py",
        ),
        unsafe_allow_html=True,
    )

    st.subheader("Evaluation")
    markdown = data.get("eval_results_markdown")
    if not markdown:
        _html(
            style.card(
                style.text_block("No evaluation yet. Run tools/evaluate_model.py to create one.")
            )
        )
    else:
        tables = helpers.parse_markdown_tables(markdown)
        if tables:
            st.dataframe(tables[0], hide_index=True, use_container_width=True)
        paragraphs = helpers.markdown_prose(markdown)
        if paragraphs:
            _html(
                style.card(
                    "".join(
                        style.text_block(p) + "<div style='height:10px'></div>" for p in paragraphs
                    ),
                    eyebrow="From docs/eval_results.md",
                )
            )

    st.subheader("Trained models")
    if data["models"]:
        st.dataframe(pd.DataFrame(data["models"]), hide_index=True, use_container_width=True)
    else:
        st.caption("No models in data/models.")
    st.subheader("Recorded baselines")
    if data["baselines"]:
        st.dataframe(pd.DataFrame(data["baselines"]), hide_index=True, use_container_width=True)
    else:
        st.caption("No baselines in data/baselines.")


# --- Train page ---------------------------------------------------------------------


@st.fragment(run_every=2)
def _training_panel(client: ConnectorClient, paragraph_index: int) -> None:
    try:
        status = client.training()
    except ApiError as error:
        _error_card(error)
        return

    baseline = status["baseline"]
    model = status["model"]
    session = status["session"]
    minimum, recommended = status["minimum_windows"], status["recommended_windows"]
    active = bool(session) and session["state"] in ("requested", "recording")

    # A new saved session means a new paragraph: refresh the whole page once.
    seen = st.session_state.get("train_saved_seen")
    st.session_state["train_saved_seen"] = status["saved_sessions"]
    if seen is not None and status["saved_sessions"] != seen:
        st.rerun(scope="app")

    columns = st.columns(3)
    columns[0].markdown(
        style.stat_card(
            "Runtime",
            "Running" if status["runtime_running"] else "Not running",
            "Records your typing through Raw Input" if status["runtime_running"]
            else "Start it with .\\tasks.ps1 run-all",
        ),
        unsafe_allow_html=True,
    )
    columns[1].markdown(
        style.stat_card(
            "Baseline",
            f"{baseline['n_windows']} of {recommended} windows",
            helpers.baseline_progress(baseline["n_windows"], minimum, recommended),
        ),
        unsafe_allow_html=True,
    )
    columns[2].markdown(
        style.stat_card(
            "Model",
            "Trained" if model["exists"] else "Not trained",
            model["version"] or "Protection starts once a model is trained",
        ),
        unsafe_allow_html=True,
    )

    if not status["runtime_running"]:
        _html(
            style.card(
                style.text_block(
                    "Recording needs the HID Firewall runtime, because it captures your typing "
                    "from the physical keyboard exactly the way detection does. Start it with "
                    ".\\tasks.ps1 run-all and approve the administrator prompt."
                ),
                title="Runtime not running",
                amber=True,
            )
        )

    if active:
        if session["state"] == "requested":
            st.caption("Waiting for the runtime to start recording...")
        else:
            st.markdown(
                f"**Recording.** {session['presses']} key presses so far. Type the paragraph "
                "below at your usual pace, then stop and save. Detection is paused while you "
                "record."
            )
        if st.button("Stop and save", type="primary", key="train_stop"):
            client.training_stop()
            st.rerun(scope="fragment")
    else:
        if session and session["state"] == "saved":
            st.success(f"Last session saved: {session['windows_saved']} windows added.")
        elif session and session["state"] in ("failed", "cancelled") and session["message"]:
            st.warning(session["message"])
        if st.button(
            "Start recording",
            type="primary",
            key="train_start",
            disabled=not status["runtime_running"],
        ):
            client.training_start(paragraph_index)
            st.rerun(scope="fragment")

    st.divider()
    left, right = st.columns([1, 1])
    can_train = baseline["n_windows"] >= minimum and not active
    if left.button("Train model", key="train_model", disabled=not can_train,
                   use_container_width=True):
        with st.spinner("Training on your baseline"):
            try:
                result = client.training_train()
            except ApiError as error:
                st.error(str(error))
            else:
                st.success(
                    f"Model {result['model']['version']} trained. The runtime starts using it "
                    "within a few seconds."
                )
    with right.popover("Start over", use_container_width=True, disabled=active):
        st.write(
            "Delete the recorded baseline and record from scratch, for example after "
            "switching keyboards. A trained model keeps protecting you until you retrain."
        )
        if st.button("Delete baseline", key="train_reset"):
            client.training_reset()
            st.rerun(scope="fragment")


def page_train(client: ConnectorClient) -> None:
    _page_header(
        "Train",
        "Teach Continuum your typing rhythm. Start recording, type the paragraph at your usual "
        "pace on the keyboard you normally use, then stop and save. Repeat with the next "
        "paragraph until the baseline is large enough, then train.",
    )
    st.caption(
        "Only key timing is recorded, through the same Raw Input capture detection uses; never "
        "which keys you press. What you type in the box stays in this browser."
    )
    try:
        saved_sessions = client.training()["saved_sessions"]
    except ApiError as error:
        _error_card(error)
        return
    passages = helpers.typing_passages(resolve_corpus_path(get_settings()))
    paragraph_index, passage = helpers.passage_for_session(passages, saved_sessions)

    _training_panel(client, paragraph_index)

    st.subheader(f"Paragraph {paragraph_index + 1} of {len(passages)}")
    if saved_sessions == 2:
        st.caption("For this one, type faster than usual: fast typing is still you.")
    components.html(style.typing_box(passage), height=390)


# --- page 5: settings ---------------------------------------------------------------


def page_settings(client: ConnectorClient) -> None:
    _page_header(
        "Settings",
        "Detection sensitivity, what Continuum does when it blocks a device, and which "
        "devices it must never block. Saved to config/local.yaml; the runtime applies them "
        "the next time it starts.",
    )
    current = client.get_settings()
    saved = current["settings"]
    runtime = _runtime(client)
    calibrated = runtime.get("calibrated_threshold")
    if calibrated is None:
        models = [m for m in _calibration(client)["models"] if "error" not in m]
        if models:
            calibrated = max(models, key=lambda m: m["modified_at"])["calibrated_threshold"]

    if current["env_overridden_fields"]:
        _html(
            style.card(
                style.text_block(
                    "These values are set by environment variables, which take precedence over "
                    "anything saved here: " + ", ".join(current["env_overridden_fields"])
                ),
                title="Environment overrides active",
                amber=True,
            )
        )

    st.subheader("Detection sensitivity")
    sensitivity = st.slider(
        "Sensitivity",
        min_value=MIN_SENSITIVITY,
        max_value=MAX_SENSITIVITY,
        value=saved["sensitivity"],
        help=f"{DEFAULT_SENSITIVITY} uses the model's calibrated threshold unchanged.",
    )
    preview = helpers.sensitivity_description(sensitivity)
    if calibrated is not None:
        threshold = calibrated + threshold_offset_for_sensitivity(sensitivity)
        preview += f". Threshold {threshold:.4f}, calibrated value {calibrated:.4f}."
    st.caption(preview)

    st.subheader("Response")
    modes = list(helpers.RESPONSE_MODE_LABELS)
    mode = st.radio(
        "Response mode",
        modes,
        index=modes.index(saved["response_mode"]),
        format_func=helpers.mode_label,
        horizontal=True,
    )
    if mode == "lock_and_disable" and runtime.get("elevated") is False:
        st.caption(
            "The runtime is not elevated, so it will fall back to lock only until it is "
            "started from an Administrator prompt."
        )
    dry_run = st.toggle(
        "Dry run: log every decision but never lock or disable anything",
        value=saved["dry_run"],
    )

    st.subheader("Allowlist")
    st.caption(
        "Devices listed here are never blocked. Use the full Windows device instance id, not "
        "just the vendor and product id, which any attack tool can imitate."
    )
    attached = {
        d["device_id"]: f"{d['name']}  ({d['device_id']})" for d in runtime.get("devices") or []
    }
    to_add = st.multiselect(
        "Add an attached keyboard",
        [device_id for device_id in attached if device_id not in saved["allowlist"]],
        format_func=lambda device_id: attached[device_id],
    )
    edited = st.data_editor(
        pd.DataFrame({"device instance id": saved["allowlist"]}, dtype="string"),
        num_rows="dynamic",
        hide_index=True,
        use_container_width=True,
        key="allowlist_editor",
    )
    allowlist = helpers.parse_allowlist_text(
        "\n".join(str(v) for v in edited["device instance id"].dropna()) + "\n" + "\n".join(to_add)
    )

    if st.button("Save settings", type="primary"):
        try:
            saved = client.put_settings(
                {
                    "sensitivity": sensitivity,
                    "response_mode": mode,
                    "dry_run": dry_run,
                    "allowlist": allowlist,
                }
            )["settings"]
        except ApiError as error:
            st.error(str(error))
        else:
            _calibration.clear()
            st.session_state.pop("allowlist_editor", None)
            st.success("Saved to config/local.yaml. Restart the runtime to apply.")

    if runtime["running"]:
        pending = []
        if runtime.get("sensitivity") != saved["sensitivity"]:
            pending.append(f"sensitivity {runtime['sensitivity']} to {saved['sensitivity']}")
        if runtime.get("configured_mode") != saved["response_mode"]:
            pending.append(
                f"response mode {helpers.mode_label(runtime['configured_mode'])} to "
                f"{helpers.mode_label(saved['response_mode'])}"
            )
        if runtime.get("dry_run") != saved["dry_run"]:
            pending.append(f"dry run {runtime['dry_run']} to {saved['dry_run']}")
        if pending:
            _html(
                style.card(
                    style.text_block("Saved but not yet applied: " + "; ".join(pending) + "."),
                    title="Restart the runtime to apply",
                    amber=True,
                )
            )

    _html(
        style.card(
            style.text_block(
                "Whatever is saved here, Continuum never disables the last remaining keyboard "
                "or an allowlisted device, re-enables every disabled device after the "
                "auto-release timeout, and releases everything at once with:\n"
                "python -m continuum.runtime --release-all"
            ),
            title="Safety rails that settings cannot turn off",
        )
    )


# --- entry point ---------------------------------------------------------------------


def _setup_problem(message: str) -> None:
    _page_header("Continuum", "The dashboard could not start.")
    _html(style.card(style.text_block(message), title="Setup needed", amber=True))
    st.stop()


def main() -> None:
    st.set_page_config(
        page_title="Continuum",
        page_icon=":material/shield:",
        layout="wide",
        initial_sidebar_state="expanded",
    )
    _html(style.CSS)

    settings = get_settings()
    token = os.environ.get(settings.connector.auth_token_env_var, "")
    if not token:
        _setup_problem(
            f"No API token found. Copy .env.example to .env, set "
            f"{settings.connector.auth_token_env_var} to the same value the connector uses, "
            "and restart the dashboard."
        )
    client = _client(f"http://{settings.connector.host}:{settings.connector.port}", token)

    page = _sidebar(client)
    renderers = {
        PAGE_LIVE: page_live,
        PAGE_INCIDENTS: page_incidents,
        PAGE_ASK: page_ask,
        PAGE_CALIBRATION: page_calibration,
        PAGE_SETTINGS: page_settings,
        PAGE_TRAIN: page_train,
    }
    try:
        renderers[page](client)
    except ApiError as error:
        _error_card(error)


if __name__ == "__main__":  # `streamlit run` executes this file as __main__
    main()

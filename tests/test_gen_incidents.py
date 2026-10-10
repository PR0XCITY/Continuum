"""Tests for tools/gen_incidents.py."""

from __future__ import annotations

from collections import Counter
from datetime import UTC, datetime, timedelta

import httpx
from tests.conftest import CONNECTOR_TEST_TOKEN
from tools.gen_incidents import (
    NOTABLE_INCIDENTS,
    generate_incidents,
    post_incidents,
    summarise,
)

from continuum.common.schemas import IncidentRecord
from continuum.connector import db

ANCHOR = datetime(2026, 10, 1, tzinfo=UTC)


def test_generation_is_reproducible_for_the_same_seed():
    first = generate_incidents(seed=42, anchor=ANCHOR)
    second = generate_incidents(seed=42, anchor=ANCHOR)

    assert [i.model_dump() for i in first] == [i.model_dump() for i in second]


def test_different_seeds_give_different_incidents():
    first = generate_incidents(seed=1, anchor=ANCHOR)
    second = generate_incidents(seed=2, anchor=ANCHOR)

    assert {i.incident_id for i in first}.isdisjoint({i.incident_id for i in second})


def test_ids_do_not_depend_on_the_anchor_date():
    first = generate_incidents(anchor=ANCHOR)
    second = generate_incidents(anchor=ANCHOR + timedelta(days=30))

    assert [i.incident_id for i in first] == [i.incident_id for i in second]


def test_generates_the_requested_count_with_unique_ids():
    incidents = generate_incidents(count=250, anchor=ANCHOR)

    assert len(incidents) == 250
    assert len({i.incident_id for i in incidents}) == 250
    assert all(isinstance(i, IncidentRecord) for i in incidents)


def test_incidents_are_spread_over_the_last_ninety_days():
    incidents = generate_incidents(anchor=ANCHOR)
    ages = [ANCHOR - i.detected_at for i in incidents]

    assert all(timedelta(0) <= age <= timedelta(days=90) for age in ages)
    assert max(ages) > timedelta(days=75)
    assert min(ages) < timedelta(days=10)


def test_incidents_have_realistic_variety():
    incidents = generate_incidents(anchor=ANCHOR)
    patterns = Counter(i.attack_pattern.value for i in incidents)
    actions = Counter(i.action_taken.value for i in incidents)
    vendor_product_pairs = {(i.device.vendor_id, i.device.product_id) for i in incidents}

    assert set(patterns) == {
        "burst_injection",
        "slowed_injection",
        "randomized_injection",
        "unknown",
    }
    assert actions["alert_only"] > 0
    assert actions["locked_and_disabled"] > actions["alert_only"]
    assert 3 <= sum(1 for i in incidents if i.notes.startswith("False positive")) <= 40
    assert 5 <= len(vendor_product_pairs) <= 15


def test_notable_incidents_come_first_in_order():
    incidents = generate_incidents(anchor=ANCHOR)

    for incident, spec in zip(incidents, NOTABLE_INCIDENTS, strict=False):
        assert incident.notes == spec["notes"]


def test_summarise_mentions_the_count():
    assert summarise(generate_incidents(anchor=ANCHOR)).startswith("200 incidents")


def test_post_incidents_through_the_real_connector(connector_client, connector_app):
    incidents = generate_incidents(anchor=ANCHOR)[:10]

    first = post_incidents(incidents, connector_client, CONNECTOR_TEST_TOKEN)
    second = post_incidents(incidents, connector_client, CONNECTOR_TEST_TOKEN)

    assert first == Counter({"created": 10})
    assert second == Counter({"already_exists": 10})

    session = connector_app.state.session_factory()
    try:
        queued = session.execute(db.select(db.RagIngestQueueRow)).scalars().all()
        assert len(queued) == 10
    finally:
        session.close()


def test_post_incidents_reports_rejected_requests(connector_client):
    incidents = generate_incidents(anchor=ANCHOR)[:2]

    outcomes = post_incidents(incidents, connector_client, "wrong-token")

    assert outcomes == Counter({"http_401": 2})


def test_post_incidents_retries_after_rate_limiting():
    calls = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request)
        if len(calls) == 1:
            return httpx.Response(429, json={"detail": "rate limit exceeded"})
        return httpx.Response(201, json={"incident_id": "x", "status": "created"})

    client = httpx.Client(transport=httpx.MockTransport(handler), base_url="http://test")
    sleeps = []

    outcomes = post_incidents(
        generate_incidents(anchor=ANCHOR)[:1], client, "token", sleep=sleeps.append
    )

    assert outcomes == Counter({"created": 1})
    assert len(calls) == 2
    assert len(sleeps) == 1

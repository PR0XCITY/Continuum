"""Tests for continuum.rag.retrieve: ranking, fusion, and filters.

Ranking tests use the fake_embeddings fixture (see conftest.py) so
they never need the real sentence-transformers model or network
access; they still exercise the real ChromaDB query path.
"""

from __future__ import annotations

from continuum.rag import ingest, retrieve


def _collection(tmp_path):
    return ingest.get_chroma_collection(tmp_path / "chroma", "test_collection")


def _seed_tiny_corpus(collection):
    ingest.ingest_playbook_document(
        "burst-playbook",
        "Burst injection attacks type keystrokes extremely fast with no "
        "variation, a clear sign of a scripted USB Rubber Ducky payload.",
        "hash-burst",
        collection,
        title="Burst injection guidance",
    )
    ingest.ingest_playbook_document(
        "false-positive-playbook",
        "A barcode scanner or macro keyboard can sometimes look like an "
        "injection attack even though it is a legitimate device.",
        "hash-fp",
        collection,
        title="False positive triage",
    )
    ingest.ingest_playbook_document(
        "mitre-playbook",
        "MITRE ATT&CK technique T1200 covers hardware additions such as "
        "malicious HID emulating devices introduced into an environment.",
        "hash-mitre",
        collection,
        title="MITRE technique reference",
    )


# --- bm25_scores ------------------------------------------------------------


def test_bm25_scores_ranks_matching_document_higher():
    documents = [
        "the quick brown fox jumps over the lazy dog",
        "completely unrelated text about something else entirely",
    ]
    scores = retrieve.bm25_scores("quick fox", documents)
    assert scores[0] > scores[1]


def test_bm25_scores_handles_empty_document_list():
    assert retrieve.bm25_scores("anything", []) == []


def test_bm25_scores_zero_for_no_term_overlap():
    documents = ["aaa bbb ccc"]
    scores = retrieve.bm25_scores("xyz", documents)
    assert scores == [0.0]


# --- reciprocal_rank_fusion --------------------------------------------------


def test_reciprocal_rank_fusion_rewards_items_ranked_high_in_both_lists():
    fused = retrieve.reciprocal_rank_fusion([["a", "b", "c"], ["b", "a", "c"]])
    assert fused["a"] > fused["c"]
    assert fused["b"] > fused["c"]


def test_reciprocal_rank_fusion_rewards_consistent_top_rank():
    fused = retrieve.reciprocal_rank_fusion([["a", "b"], ["a", "b"]])
    assert fused["a"] > fused["b"]


# --- hybrid_retrieve (ranking on a tiny fixture corpus) ---------------------


def test_hybrid_retrieve_ranks_relevant_chunk_first(tmp_path, fake_embeddings):
    collection = _collection(tmp_path)
    _seed_tiny_corpus(collection)

    results = retrieve.hybrid_retrieve(collection, "USB Rubber Ducky burst injection", top_k=3)

    assert results
    assert results[0].doc_id == "burst-playbook"


def test_hybrid_retrieve_respects_top_k(tmp_path, fake_embeddings):
    collection = _collection(tmp_path)
    _seed_tiny_corpus(collection)

    results = retrieve.hybrid_retrieve(collection, "injection attack", top_k=1)

    assert len(results) == 1


def test_hybrid_retrieve_filters_by_source_type(tmp_path, fake_embeddings):
    collection = _collection(tmp_path)
    _seed_tiny_corpus(collection)
    ingest.ingest_incident_document(
        "inc-1",
        "Incident inc-1\n"
        "Detected at: 2026-01-01T00:00:00+00:00\n"
        "Device: Test Keyboard (dev-1, USB, vendor 046D product C52B)\n"
        "Verdict: blocked\n"
        "Attack pattern: burst_injection\n"
        "Anomaly score: 2.500 (threshold 1.000)\n"
        "Action taken: locked_and_disabled\n"
        "Time to detect: 450 ms\n"
        "MITRE technique: T1200\n"
        "Recommended followups: none\n"
        "Notes:\n",
        collection,
    )

    results = retrieve.hybrid_retrieve(
        collection, "burst injection", top_k=5, source_type="incident"
    )

    assert results
    assert all(r.source_type == "incident" for r in results)


def test_hybrid_retrieve_returns_empty_for_empty_collection(tmp_path, fake_embeddings):
    collection = _collection(tmp_path)
    results = retrieve.hybrid_retrieve(collection, "anything at all", top_k=5)
    assert results == []

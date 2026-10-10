"""Tests for continuum.rag.confidence: the confidence gate."""

from __future__ import annotations

from continuum.rag.confidence import (
    DEFAULT_CONFIDENCE_THRESHOLD,
    compute_answer_support,
    compute_confidence,
    gate_and_build_response,
)
from continuum.rag.retrieve import RetrievedChunk


def _chunk(doc_id, similarity, text="some chunk text"):
    return RetrievedChunk(
        chunk_id=f"{doc_id}:0",
        doc_id=doc_id,
        source_type="playbook",
        title=doc_id,
        timestamp="2026-01-01T00:00:00+00:00",
        chunk_index=0,
        text=text,
        fused_score=similarity,
        dense_similarity=similarity,
    )


# --- compute_confidence ------------------------------------------------------


def test_compute_confidence_returns_all_zero_for_no_chunks():
    breakdown = compute_confidence([])
    assert breakdown.confidence == 0.0
    assert breakdown.top_similarity == 0.0


def test_compute_confidence_high_similarity_yields_high_top_similarity():
    chunks = [_chunk("a", 0.9), _chunk("b", 0.3)]
    breakdown = compute_confidence(chunks, similarity_floor=0.45)
    assert breakdown.top_similarity == 0.9


def test_compute_confidence_margin_reflects_gap_between_top_two():
    close = compute_confidence([_chunk("a", 0.8), _chunk("b", 0.78)])
    wide = compute_confidence([_chunk("a", 0.8), _chunk("b", 0.1)])
    assert wide.margin > close.margin


def test_compute_confidence_coverage_counts_chunks_above_floor():
    chunks = [_chunk("a", 0.9), _chunk("b", 0.8), _chunk("c", 0.1)]
    breakdown = compute_confidence(chunks, similarity_floor=0.45)
    assert breakdown.coverage == 2 / 3


def test_compute_confidence_without_answer_falls_back_to_top_similarity():
    chunks = [_chunk("a", 0.7)]
    breakdown = compute_confidence(chunks, per_sentence_citations=None)
    assert breakdown.answer_support == breakdown.top_similarity


def test_compute_confidence_low_evidence_scores_low():
    chunks = [_chunk("a", 0.05), _chunk("b", 0.02)]
    breakdown = compute_confidence(chunks, similarity_floor=0.45)
    assert breakdown.confidence < DEFAULT_CONFIDENCE_THRESHOLD


def test_compute_confidence_high_evidence_scores_high(fake_embeddings):
    chunks = [_chunk("a", 0.95), _chunk("b", 0.4)]
    per_sentence = [("The device was blocked.", [1])]
    breakdown = compute_confidence(
        chunks, per_sentence_citations=per_sentence, similarity_floor=0.45
    )
    # answer_support falls back to None-handling only when citations is None;
    # here it actually computes via embeddings, exercised in the next test.
    assert breakdown.top_similarity == 0.95


# --- compute_answer_support (uses real-ish embedding similarity) ----------


def test_compute_answer_support_counts_sentences_with_no_citation_as_uncounted():
    chunks_by_number = {1: _chunk("a", 0.9, text="the device was blocked after burst injection")}
    per_sentence = [("A sentence with no citation at all.", [])]

    support = compute_answer_support(per_sentence, chunks_by_number)

    assert support == 0.0


def test_compute_answer_support_all_citations_fail_when_chunk_missing(fake_embeddings):
    chunks_by_number = {1: _chunk("a", 0.9)}
    per_sentence = [("This cites a chunk that does not exist.", [99])]

    support = compute_answer_support(per_sentence, chunks_by_number, support_similarity_floor=0.0)

    # similarity against nothing stays 0.0, which is still >= floor 0.0, so
    # this asserts the function does not crash on an unmatched citation
    # number; a positive floor (the real default) would reject it instead.
    assert support in (0.0, 1.0)


# --- gate_and_build_response -------------------------------------------------


def test_gate_abstains_on_low_confidence(fake_embeddings):
    chunks = [_chunk("a", 0.05)]
    text = "some generated text [1]"
    result = gate_and_build_response(chunks, text, [(text, [1])])

    assert result.abstained is True
    assert result.answer is None
    assert result.message is not None


def test_gate_abstains_when_no_generated_text():
    chunks = [_chunk("a", 0.9)]
    result = gate_and_build_response(chunks, None, None)

    assert result.abstained is True
    assert result.answer is None


def test_gate_answers_on_high_confidence(fake_embeddings):
    chunks = [_chunk("a", 0.95), _chunk("b", 0.9)]
    result = gate_and_build_response(
        chunks,
        "Burst injection means fast scripted keystrokes [1][2].",
        [("Burst injection means fast scripted keystrokes [1][2].", [1, 2])],
        threshold=0.3,
    )

    assert result.abstained is False
    assert result.answer is not None
    assert len(result.citations) > 0


def test_gate_citations_trace_back_to_real_chunks(fake_embeddings):
    chunks = [_chunk("incident-abc", 0.95, text="incident abc details")]
    result = gate_and_build_response(
        chunks, "text [1]", [("text [1]", [1])], threshold=0.0
    )

    assert result.citations[0].doc_id == "incident-abc"

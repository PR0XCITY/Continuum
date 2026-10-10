"""The confidence gate: decides whether IncidentRAG has enough evidence to answer.

Responsibility: compute a single confidence score (0 to 1) from four
signals, and gate the final answer behind it. "I don't know" is a
valid and safe output of this gate, not a failure. Never returns a
guessed answer when evidence is weak.

Signals, weighted and summed:
    top_similarity    the best retrieved chunk's dense cosine similarity.
    margin             gap between the best and second-best similarity;
                        a flat ranking is weaker evidence than a clear
                        winner even at the same top score.
    coverage            fraction of retrieved chunks at or above the
                        similarity floor (settings.rag.min_similarity).
    answer_support      fraction of the generated answer's citing
                        sentences whose embedding is actually similar
                        to the chunk(s) they cite. Requires an
                        already-generated answer; falls back to
                        top_similarity when there isn't one yet (pure
                        retrieval-confidence use, e.g. before calling
                        the LLM at all).
"""

from __future__ import annotations

from dataclasses import dataclass

import numpy as np

from continuum.rag.embed import embed_one
from continuum.rag.retrieve import RetrievedChunk

DEFAULT_SIMILARITY_FLOOR = 0.45
DEFAULT_CONFIDENCE_THRESHOLD = 0.5
DEFAULT_ANSWER_SUPPORT_FLOOR = 0.3
DEFAULT_WEIGHTS = (0.35, 0.15, 0.15, 0.35)  # top_similarity, margin, coverage, answer_support

ABSTENTION_MESSAGE = "Not enough evidence in the incident records to answer this reliably."


@dataclass(frozen=True)
class ConfidenceBreakdown:
    top_similarity: float
    margin: float
    coverage: float
    answer_support: float
    confidence: float


@dataclass(frozen=True)
class Citation:
    doc_id: str
    title: str
    snippet: str
    score: float


@dataclass(frozen=True)
class RagAnswer:
    answer: str | None
    confidence: float
    abstained: bool
    citations: list[Citation]
    message: str | None = None


def compute_answer_support(
    per_sentence_citations: list[tuple[str, list[int]]],
    chunks_by_number: dict[int, RetrievedChunk],
    *,
    support_similarity_floor: float = DEFAULT_ANSWER_SUPPORT_FLOOR,
) -> float:
    """Fraction of citing sentences whose embedding matches a chunk they cite.

    A sentence with no citations at all is not counted either way (it
    makes no claim to check); if no sentence cites anything, there is
    nothing to support and the result is 0.0.
    """
    citing_sentences = [(s, nums) for s, nums in per_sentence_citations if nums]
    if not citing_sentences:
        return 0.0

    supported = 0
    for sentence, numbers in citing_sentences:
        sentence_embedding = embed_one(sentence)
        best_similarity = 0.0
        for number in numbers:
            chunk = chunks_by_number.get(number)
            if chunk is None:
                continue
            chunk_embedding = embed_one(chunk.text)
            similarity = float(np.dot(sentence_embedding, chunk_embedding))
            best_similarity = max(best_similarity, similarity)
        if best_similarity >= support_similarity_floor:
            supported += 1

    return supported / len(citing_sentences)


def compute_confidence(
    chunks: list[RetrievedChunk],
    *,
    per_sentence_citations: list[tuple[str, list[int]]] | None = None,
    similarity_floor: float = DEFAULT_SIMILARITY_FLOOR,
    support_similarity_floor: float = DEFAULT_ANSWER_SUPPORT_FLOOR,
    weights: tuple[float, float, float, float] = DEFAULT_WEIGHTS,
) -> ConfidenceBreakdown:
    if not chunks:
        return ConfidenceBreakdown(0.0, 0.0, 0.0, 0.0, 0.0)

    similarities = [c.dense_similarity for c in chunks]
    top_similarity = max(0.0, min(1.0, similarities[0]))
    if len(similarities) > 1:
        margin = max(0.0, min(1.0, similarities[0] - similarities[1]))
    else:
        margin = top_similarity
    coverage = sum(1 for s in similarities if s >= similarity_floor) / len(similarities)

    if per_sentence_citations is not None:
        chunks_by_number = dict(enumerate(chunks, start=1))
        answer_support = compute_answer_support(
            per_sentence_citations,
            chunks_by_number,
            support_similarity_floor=support_similarity_floor,
        )
    else:
        # No answer to check yet: fall back to the retrieval-only signal.
        answer_support = top_similarity

    w1, w2, w3, w4 = weights
    confidence = w1 * top_similarity + w2 * margin + w3 * coverage + w4 * answer_support
    confidence = max(0.0, min(1.0, confidence))

    return ConfidenceBreakdown(
        top_similarity=top_similarity,
        margin=margin,
        coverage=coverage,
        answer_support=answer_support,
        confidence=confidence,
    )


def best_possible_confidence(
    chunks: list[RetrievedChunk],
    *,
    similarity_floor: float = DEFAULT_SIMILARITY_FLOOR,
    weights: tuple[float, float, float, float] = DEFAULT_WEIGHTS,
) -> float:
    """Confidence if a generated answer were perfectly supported by its sources.

    Answer support is the only signal an LLM answer can add, and it is at
    most 1.0. If even that cannot reach the threshold, no answer could
    pass the gate, so the LLM need not be called at all.
    """
    breakdown = compute_confidence(chunks, similarity_floor=similarity_floor, weights=weights)
    answer_weight = weights[3]
    return min(1.0, breakdown.confidence - answer_weight * breakdown.answer_support + answer_weight)


def build_citations(chunks: list[RetrievedChunk], *, limit: int = 5) -> list[Citation]:
    return [
        Citation(doc_id=c.doc_id, title=c.title, snippet=c.text[:200], score=c.dense_similarity)
        for c in chunks[:limit]
    ]


def gate_and_build_response(
    chunks: list[RetrievedChunk],
    generated_text: str | None,
    per_sentence_citations: list[tuple[str, list[int]]] | None,
    *,
    threshold: float = DEFAULT_CONFIDENCE_THRESHOLD,
    similarity_floor: float = DEFAULT_SIMILARITY_FLOOR,
    support_similarity_floor: float = DEFAULT_ANSWER_SUPPORT_FLOOR,
) -> RagAnswer:
    """Combine retrieval and (if present) answer-support signals into a verdict.

    Abstains, with the closest sources attached for a human to read
    manually, whenever confidence falls below threshold or there is no
    generated answer at all (for example because Ollama was
    unreachable and the caller never got that far).
    """
    breakdown = compute_confidence(
        chunks,
        per_sentence_citations=per_sentence_citations,
        similarity_floor=similarity_floor,
        support_similarity_floor=support_similarity_floor,
    )
    citations = build_citations(chunks)

    if generated_text is None or breakdown.confidence < threshold:
        return RagAnswer(
            answer=None,
            confidence=breakdown.confidence,
            abstained=True,
            citations=citations,
            message=ABSTENTION_MESSAGE,
        )

    return RagAnswer(
        answer=generated_text,
        confidence=breakdown.confidence,
        abstained=False,
        citations=citations,
        message=None,
    )

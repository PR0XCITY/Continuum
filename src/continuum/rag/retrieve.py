"""Hybrid retrieval over the IncidentRAG corpus.

Responsibility: given a question, return the top-k most relevant
chunks from ChromaDB. Combines two rankings:

    dense     cosine similarity between the query embedding and each
              chunk's stored embedding (ChromaDB's own query()).
    sparse    a small, dependency-free BM25 implementation over the
              dense candidate pool's text, catching exact keyword or
              identifier matches (device ids, MITRE technique codes)
              that an embedding alone can miss or dilute.

The two rankings are fused with reciprocal rank fusion (RRF) rather
than averaged, so the result does not depend on the two scores being
on comparable scales.
"""

from __future__ import annotations

import math
import re
from collections import Counter
from dataclasses import dataclass

from continuum.rag.embed import embed_one

DEFAULT_TOP_K = 5
DEFAULT_CANDIDATE_POOL_SIZE = 20
DEFAULT_RRF_K = 60

_WORD_PATTERN = re.compile(r"[a-z0-9]+")


@dataclass(frozen=True)
class RetrievedChunk:
    chunk_id: str
    doc_id: str
    source_type: str
    title: str
    timestamp: str
    chunk_index: int
    text: str
    fused_score: float
    dense_similarity: float


def _tokenize(text: str) -> list[str]:
    return _WORD_PATTERN.findall(text.lower())


def bm25_scores(
    query: str, documents: list[str], *, k1: float = 1.5, b: float = 0.75
) -> list[float]:
    """BM25 score of query against each document, in the given order.

    Recomputed fresh over just the candidate documents passed in, not
    the whole corpus; fine for a college-project-sized incident and
    playbook collection, and keeps this function pure and easy to test.
    """
    if not documents:
        return []

    tokenized_docs = [_tokenize(doc) for doc in documents]
    doc_lengths = [len(doc) for doc in tokenized_docs]
    avg_doc_length = (sum(doc_lengths) / len(doc_lengths)) if doc_lengths else 0.0
    n_docs = len(documents)

    query_terms = _tokenize(query)
    term_doc_freq = {
        term: sum(1 for doc in tokenized_docs if term in doc) for term in set(query_terms)
    }

    scores = []
    for doc_tokens, doc_length in zip(tokenized_docs, doc_lengths, strict=True):
        term_counts = Counter(doc_tokens)
        score = 0.0
        for term in query_terms:
            df = term_doc_freq.get(term, 0)
            if df == 0:
                continue
            idf = math.log(1 + (n_docs - df + 0.5) / (df + 0.5))
            tf = term_counts.get(term, 0)
            length_norm = doc_length / avg_doc_length if avg_doc_length else 1.0
            denom = tf + k1 * (1 - b + b * length_norm)
            if denom:
                score += idf * (tf * (k1 + 1)) / denom
        scores.append(score)
    return scores


def reciprocal_rank_fusion(
    rankings: list[list[str]], *, k: int = DEFAULT_RRF_K
) -> dict[str, float]:
    """Combine several ranked id lists into one fused score per id."""
    fused: dict[str, float] = {}
    for ranking in rankings:
        for rank, item_id in enumerate(ranking, start=1):
            fused[item_id] = fused.get(item_id, 0.0) + 1.0 / (k + rank)
    return fused


def _build_where_filter(
    *, source_type: str | None, start_time: str | None, end_time: str | None
) -> dict | None:
    conditions = []
    if source_type is not None:
        conditions.append({"source_type": source_type})
    if start_time is not None:
        conditions.append({"timestamp": {"$gte": start_time}})
    if end_time is not None:
        conditions.append({"timestamp": {"$lte": end_time}})

    if not conditions:
        return None
    if len(conditions) == 1:
        return conditions[0]
    return {"$and": conditions}


def dense_search(
    collection, query: str, *, top_k: int, where: dict | None = None
) -> list[tuple[str, dict, str, float]]:
    """Returns (chunk_id, metadata, document_text, similarity), best first.

    Similarity is 1 - cosine distance; correct only because
    ingest.get_chroma_collection creates the collection with
    hnsw:space="cosine".
    """
    query_embedding = embed_one(query)
    results = collection.query(
        query_embeddings=[query_embedding.tolist()],
        n_results=top_k,
        where=where,
    )
    ids = results["ids"][0] if results["ids"] else []
    if not ids:
        return []
    metadatas = results["metadatas"][0]
    documents = results["documents"][0]
    distances = results["distances"][0]
    similarities = [1.0 - d for d in distances]
    return list(zip(ids, metadatas, documents, similarities, strict=True))


def hybrid_retrieve(
    collection,
    query: str,
    *,
    top_k: int = DEFAULT_TOP_K,
    source_type: str | None = None,
    start_time: str | None = None,
    end_time: str | None = None,
    candidate_pool_size: int = DEFAULT_CANDIDATE_POOL_SIZE,
) -> list[RetrievedChunk]:
    """Dense search over a candidate pool, re-ranked by RRF with BM25."""
    if collection.count() == 0:
        # Nothing to retrieve; skip embedding the query entirely.
        return []

    where = _build_where_filter(source_type=source_type, start_time=start_time, end_time=end_time)
    dense_results = dense_search(collection, query, top_k=candidate_pool_size, where=where)
    if not dense_results:
        return []

    chunk_ids = [r[0] for r in dense_results]
    metadatas = {r[0]: r[1] for r in dense_results}
    documents = {r[0]: r[2] for r in dense_results}
    dense_similarity = {r[0]: r[3] for r in dense_results}

    dense_ranking = sorted(chunk_ids, key=lambda cid: dense_similarity[cid], reverse=True)

    bm25_values = bm25_scores(query, [documents[cid] for cid in chunk_ids])
    bm25_by_id = dict(zip(chunk_ids, bm25_values, strict=True))
    bm25_ranking = sorted(chunk_ids, key=lambda cid: bm25_by_id[cid], reverse=True)

    fused_scores = reciprocal_rank_fusion([dense_ranking, bm25_ranking])
    ranked_ids = sorted(fused_scores, key=lambda cid: fused_scores[cid], reverse=True)[:top_k]

    return [
        RetrievedChunk(
            chunk_id=cid,
            doc_id=metadatas[cid]["doc_id"],
            source_type=metadatas[cid]["source_type"],
            title=metadatas[cid]["title"],
            timestamp=metadatas[cid]["timestamp"],
            chunk_index=metadatas[cid]["chunk_index"],
            text=documents[cid],
            fused_score=fused_scores[cid],
            dense_similarity=dense_similarity[cid],
        )
        for cid in ranked_ids
    ]

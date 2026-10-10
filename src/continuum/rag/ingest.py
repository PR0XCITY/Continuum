"""Build and maintain the IncidentRAG corpus in ChromaDB.

Responsibility: the only module allowed to write into the vector
store. Two corpus sources, two poisoning defences:

    incident documents   built by connector.document.render_incident_
                          document from a schema-validated
                          IncidentRecord, queued in the connector's
                          rag_ingest_queue table. Before ingesting one,
                          is_valid_incident_document() checks the text
                          still has the fixed template's exact shape;
                          anything else is rejected, not ingested, and
                          marked "rejected" in the queue so it is never
                          retried.
    playbook documents   human-authored markdown files in
                          settings.rag.corpus_path (never fetched from
                          the network at runtime). Only files actually
                          inside that directory are accepted; each
                          file's sha256 content hash is recorded in its
                          chunks' metadata, both as an audit trail and
                          to skip re-ingesting an unchanged file.

Every ingestion, accepted or rejected, is logged.
"""

from __future__ import annotations

import hashlib
import re
import sqlite3
import threading
import time
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from continuum.common.config import Settings
from continuum.common.logging import get_logger
from continuum.rag.embed import embed_texts

logger = get_logger("rag.ingest")

REPO_ROOT = Path(__file__).resolve().parents[3]


def _disable_chromadb_telemetry() -> None:
    """Hard-disable ChromaDB's posthog telemetry client, defense in depth.

    Passing anonymized_telemetry=False to chromadb's own Settings should
    be enough, but the installed chromadb/posthog version pairing has a
    signature mismatch bug that makes chromadb still attempt (and fail)
    a capture() call regardless. No data actually reaches the network
    because that call errors out before posthog's own body runs, but
    Continuum's "no telemetry, ever" rule means we never rely on a
    third-party library's internal bug for that guarantee: patch
    capture() to a true no-op ourselves.
    """
    try:
        import posthog

        posthog.disabled = True
        posthog.capture = lambda *args, **kwargs: None
    except ImportError:
        pass


_disable_chromadb_telemetry()

DEFAULT_CHUNK_SIZE_TOKENS = 300
DEFAULT_CHUNK_OVERLAP_TOKENS = 50

SOURCE_TYPE_INCIDENT = "incident"
SOURCE_TYPE_PLAYBOOK = "playbook"

# Mirrors connector.document.INCIDENT_DOCUMENT_TEMPLATE's exact line
# order and field labels. Kept here, independent of that module, as
# defense in depth: if the queue ever contained something that was not
# actually built by render_incident_document, this still catches it.
_INCIDENT_TEMPLATE_LINE_PREFIXES = (
    "Incident ",
    "Detected at:",
    "Device:",
    "Verdict:",
    "Attack pattern:",
    "Anomaly score:",
    "Action taken:",
    "Time to detect:",
    "MITRE technique:",
    "Recommended followups:",
    "Notes:",
)


@dataclass(frozen=True)
class ChunkRecord:
    chunk_id: str
    doc_id: str
    source_type: str
    title: str
    timestamp: str
    chunk_index: int
    text: str
    content_hash: str | None = None


def resolve_chroma_path(settings: Settings) -> Path:
    path = settings.rag.chroma_path
    return path if path.is_absolute() else REPO_ROOT / path


def resolve_corpus_path(settings: Settings) -> Path:
    path = settings.rag.corpus_path
    return path if path.is_absolute() else REPO_ROOT / path


def get_chroma_collection(chroma_path: Path, collection_name: str):
    """Open (creating if needed) the persistent, cosine-space Chroma collection.

    anonymized_telemetry is explicitly disabled: ChromaDB otherwise
    phones home to its own analytics endpoint on client start and on
    most collection operations, which Continuum's "everything runs
    locally, no telemetry, ever" rule forbids outright.
    """
    import chromadb
    from chromadb.config import Settings as ChromaSettings

    chroma_path.mkdir(parents=True, exist_ok=True)
    client = chromadb.PersistentClient(
        path=str(chroma_path), settings=ChromaSettings(anonymized_telemetry=False)
    )
    return client.get_or_create_collection(
        name=collection_name, metadata={"hnsw:space": "cosine"}
    )


def is_valid_incident_document(text: str) -> bool:
    """True if text has the exact fixed-template shape, field order included."""
    if not isinstance(text, str):
        return False
    lines = text.strip("\n").split("\n")
    if len(lines) < len(_INCIDENT_TEMPLATE_LINE_PREFIXES):
        return False
    return all(
        lines[i].startswith(prefix)
        for i, prefix in enumerate(_INCIDENT_TEMPLATE_LINE_PREFIXES)
    )


def chunk_text(
    text: str,
    *,
    chunk_size_tokens: int = DEFAULT_CHUNK_SIZE_TOKENS,
    overlap_tokens: int = DEFAULT_CHUNK_OVERLAP_TOKENS,
) -> list[str]:
    """Split text into overlapping chunks, sized in whitespace-separated words.

    "Tokens" here means words: a simple, dependency-free proxy for real
    subword tokens, close enough to keep chunk size predictable.
    """
    words = text.split()
    if not words:
        return []
    if len(words) <= chunk_size_tokens:
        return [text.strip()]

    step = max(chunk_size_tokens - overlap_tokens, 1)
    chunks = []
    start = 0
    while start < len(words):
        chunk_words = words[start : start + chunk_size_tokens]
        chunks.append(" ".join(chunk_words))
        if start + chunk_size_tokens >= len(words):
            break
        start += step
    return chunks


def _add_chunks_to_collection(collection, chunks: list[ChunkRecord]) -> None:
    if not chunks:
        return
    embeddings = embed_texts([c.text for c in chunks])
    # upsert, not add: re-ingesting the same chunk id (a retry after a
    # crash between embedding and marking the queue row) is a no-op.
    collection.upsert(
        ids=[c.chunk_id for c in chunks],
        embeddings=embeddings.tolist(),
        documents=[c.text for c in chunks],
        metadatas=[
            {
                "doc_id": c.doc_id,
                "source_type": c.source_type,
                "title": c.title,
                "timestamp": c.timestamp,
                "chunk_index": c.chunk_index,
                **({"content_hash": c.content_hash} if c.content_hash else {}),
            }
            for c in chunks
        ],
    )


def ingest_incident_document(
    incident_id: str,
    document_text: str,
    collection,
    *,
    detected_at: str | None = None,
    chunk_size_tokens: int = DEFAULT_CHUNK_SIZE_TOKENS,
    overlap_tokens: int = DEFAULT_CHUNK_OVERLAP_TOKENS,
) -> int:
    """Ingest one already-validated incident document. Returns chunk count.

    Raises ValueError if document_text does not match the fixed
    template; callers (process_pending_incidents) are expected to check
    is_valid_incident_document() first and treat that as a rejection,
    not let this exception propagate.
    """
    if not is_valid_incident_document(document_text):
        raise ValueError(f"incident document for {incident_id} is not the fixed template")

    texts = chunk_text(
        document_text, chunk_size_tokens=chunk_size_tokens, overlap_tokens=overlap_tokens
    )
    timestamp = detected_at or datetime.now(UTC).isoformat()
    chunks = [
        ChunkRecord(
            chunk_id=f"incident:{incident_id}:{i}",
            doc_id=incident_id,
            source_type=SOURCE_TYPE_INCIDENT,
            title=f"Incident {incident_id}",
            timestamp=timestamp,
            chunk_index=i,
            text=text,
        )
        for i, text in enumerate(texts)
    ]
    _add_chunks_to_collection(collection, chunks)
    logger.info("ingested incident %s as %d chunk(s)", incident_id, len(chunks))
    return len(chunks)


def ingest_playbook_document(
    doc_id: str,
    content: str,
    content_hash: str,
    collection,
    *,
    title: str | None = None,
    chunk_size_tokens: int = DEFAULT_CHUNK_SIZE_TOKENS,
    overlap_tokens: int = DEFAULT_CHUNK_OVERLAP_TOKENS,
) -> int:
    texts = chunk_text(
        content, chunk_size_tokens=chunk_size_tokens, overlap_tokens=overlap_tokens
    )
    chunks = [
        ChunkRecord(
            chunk_id=f"playbook:{doc_id}:{i}",
            doc_id=doc_id,
            source_type=SOURCE_TYPE_PLAYBOOK,
            title=title or doc_id,
            timestamp=datetime.now(UTC).isoformat(),
            chunk_index=i,
            text=text,
            content_hash=content_hash,
        )
        for i, text in enumerate(texts)
    ]
    _add_chunks_to_collection(collection, chunks)
    logger.info(
        "ingested playbook %s as %d chunk(s) (hash %s)", doc_id, len(chunks), content_hash[:12]
    )
    return len(chunks)


def _get_existing_playbook_hash(collection, doc_id: str) -> str | None:
    result = collection.get(where={"doc_id": doc_id}, limit=1)
    metadatas = result.get("metadatas") or []
    if not metadatas:
        return None
    return metadatas[0].get("content_hash")


def _remove_existing_chunks(collection, doc_id: str) -> None:
    existing = collection.get(where={"doc_id": doc_id})
    ids = existing.get("ids") or []
    if ids:
        collection.delete(ids=ids)


_PLAYBOOK_TITLE_PATTERN = re.compile(r"^#\s+(.+)$", re.MULTILINE)


def _extract_title(content: str, fallback: str) -> str:
    match = _PLAYBOOK_TITLE_PATTERN.search(content)
    return match.group(1).strip() if match else fallback


def ingest_corpus_directory(
    corpus_path: Path,
    collection,
    *,
    chunk_size_tokens: int = DEFAULT_CHUNK_SIZE_TOKENS,
    overlap_tokens: int = DEFAULT_CHUNK_OVERLAP_TOKENS,
) -> int:
    """Ingest every .md file under corpus_path, recursively. Returns files changed.

    doc_id is the file name without its extension, so it must be unique
    across the whole corpus; a second file with the same stem is
    skipped with a warning. Skips a file whose content hash already
    matches what is stored. Anything that resolves outside corpus_path
    (for example a symlink pointing elsewhere) is refused: playbook
    content comes only from this directory. Playbook documents whose
    file no longer exists are removed from the collection.
    """
    corpus_path = corpus_path.resolve()
    if not corpus_path.exists():
        logger.warning("corpus directory %s does not exist, nothing to ingest", corpus_path)
        return 0

    changed = 0
    seen_doc_ids: set[str] = set()
    for md_path in sorted(corpus_path.rglob("*.md")):
        resolved = md_path.resolve()
        if not resolved.is_relative_to(corpus_path):
            logger.warning("refused %s: resolves outside the corpus directory", md_path)
            continue

        doc_id = md_path.stem
        if doc_id in seen_doc_ids:
            logger.warning("skipped %s: duplicate doc_id %r", md_path, doc_id)
            continue
        seen_doc_ids.add(doc_id)

        content = resolved.read_text(encoding="utf-8")
        content_hash = hashlib.sha256(content.encode("utf-8")).hexdigest()

        existing_hash = _get_existing_playbook_hash(collection, doc_id)
        if existing_hash == content_hash:
            logger.info("playbook %s unchanged, skipping", md_path.name)
            continue

        if existing_hash is not None:
            _remove_existing_chunks(collection, doc_id)

        title = _extract_title(content, fallback=doc_id)
        ingest_playbook_document(
            doc_id,
            content,
            content_hash,
            collection,
            title=title,
            chunk_size_tokens=chunk_size_tokens,
            overlap_tokens=overlap_tokens,
        )
        changed += 1

    stored = collection.get(where={"source_type": SOURCE_TYPE_PLAYBOOK}, include=["metadatas"])
    stale_doc_ids = {m["doc_id"] for m in stored.get("metadatas") or []} - seen_doc_ids
    for doc_id in sorted(stale_doc_ids):
        _remove_existing_chunks(collection, doc_id)
        logger.info("removed playbook %s: its file no longer exists", doc_id)
        changed += 1

    return changed


# --- watching the connector's rag_ingest_queue table --------------------------


def _detected_at_from_document(document_text: str) -> str:
    """The "Detected at:" value of an already-validated incident document."""
    second_line = document_text.strip("\n").split("\n")[1]
    return second_line.removeprefix("Detected at:").strip()


def process_pending_incidents(
    connector_db_path: Path,
    collection,
    *,
    chunk_size_tokens: int = DEFAULT_CHUNK_SIZE_TOKENS,
    overlap_tokens: int = DEFAULT_CHUNK_OVERLAP_TOKENS,
) -> int:
    """One pass over the connector's rag_ingest_queue. Returns rows ingested.

    Every pending row is marked "ingested" or "rejected" so it is never
    processed twice, whichever outcome logging already recorded.
    """
    conn = sqlite3.connect(str(connector_db_path))
    try:
        rows = conn.execute(
            "SELECT id, incident_id, document_text FROM rag_ingest_queue "
            "WHERE status = 'pending'"
        ).fetchall()

        ingested_count = 0
        for row_id, incident_id, document_text in rows:
            if not is_valid_incident_document(document_text):
                logger.warning(
                    "rejected malformed incident document for %s: does not match the "
                    "fixed template",
                    incident_id,
                )
                conn.execute(
                    "UPDATE rag_ingest_queue SET status = 'rejected' WHERE id = ?", (row_id,)
                )
                continue

            ingest_incident_document(
                incident_id,
                document_text,
                collection,
                detected_at=_detected_at_from_document(document_text),
                chunk_size_tokens=chunk_size_tokens,
                overlap_tokens=overlap_tokens,
            )
            conn.execute(
                "UPDATE rag_ingest_queue SET status = 'ingested' WHERE id = ?", (row_id,)
            )
            conn.commit()
            ingested_count += 1

        conn.commit()
        return ingested_count
    finally:
        conn.close()


def watch_ingest_queue(
    connector_db_path: Path,
    collection,
    *,
    poll_interval_seconds: float = 3.0,
    max_iterations: int | None = None,
    stop_event: threading.Event | None = None,
) -> None:
    """Poll the connector's rag_ingest_queue table and ingest new incidents.

    Runs until max_iterations passes (default: forever) or stop_event is
    set, whichever comes first. The connector app runs this on a
    background thread for the lifetime of the process (see
    connector.app.create_app); tests pass a small max_iterations
    instead of running this loop unbounded.
    """
    iterations = 0
    while max_iterations is None or iterations < max_iterations:
        if stop_event is not None and stop_event.is_set():
            return
        process_pending_incidents(connector_db_path, collection)
        iterations += 1
        if max_iterations is not None and iterations >= max_iterations:
            return
        if stop_event is not None:
            if stop_event.wait(timeout=poll_interval_seconds):
                return
        else:
            time.sleep(poll_interval_seconds)

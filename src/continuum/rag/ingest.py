"""Incident ingestion into the RAG corpus.

Responsibility: read incidents (typically from the connector's SQLite
store), validate each one against common.schemas.Incident, render it into
a document chunk, and write it into ChromaDB at the configured path.
Anything that fails schema validation is rejected and never reaches the
corpus; there is no path from unvalidated free text into ChromaDB.
"""

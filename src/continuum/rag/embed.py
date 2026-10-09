"""Embedding for the RAG corpus and queries.

Responsibility: load the sentence-transformers all-MiniLM-L6-v2 model once
and provide a single embed() function used identically by ingest.py (for
documents) and retrieve.py (for queries), so both sides of the search are
always embedded the same way. Runs fully locally; no network call.
"""

"""IncidentRAG: local retrieval-augmented incident-response assistant.

Responsibility: ingest schema-validated incidents into a local vector
store, embed and retrieve relevant passages for an analyst's question,
gate the answer behind a confidence check, and generate a cited answer
using a local Ollama model. Never calls out to any network service other
than the local Ollama HTTP API on 127.0.0.1.

Modules:
    embed.py      Wraps sentence-transformers (all-MiniLM-L6-v2) embedding
                  of corpus documents and queries. Loads the model lazily,
                  on first use, so importing continuum.rag stays cheap.
    ingest.py     The only module allowed to write into the ChromaDB
                  corpus. Chunks documents with overlap, and enforces the
                  poisoning defences: an incident document is only
                  ingested if it still has the fixed template's exact
                  shape; a playbook document is only ingested from
                  settings.rag.corpus_path, with a recorded content hash.
                  Watches the connector's rag_ingest_queue table and
                  ingests new incidents within a few seconds.
    retrieve.py   Hybrid retrieval: dense (embedding) similarity fused
                  with a small built-in BM25 score via reciprocal rank
                  fusion. Supports source_type and date-range filters.
    confidence.py Scores retrieval and answer-support quality and gates
                  the final answer behind a single confidence score.
                  "I don't know" is a valid and safe output of this gate,
                  not a failure mode.
    answer.py     Builds the cited prompt, wrapping every retrieved chunk
                  (incident notes included) as quoted data so it cannot
                  act as an instruction, calls the local Ollama HTTP API
                  (http://127.0.0.1:11434) to generate the answer, and
                  verifies every citation number against the chunks
                  actually retrieved. answer_question() is the single
                  entry point the connector's /query route and
                  tools/rag_cli.py both call.
"""

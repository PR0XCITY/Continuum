"""IncidentRAG: local retrieval-augmented incident-response assistant.

Responsibility: ingest schema-validated incidents into a local vector
store, embed and retrieve relevant passages for an analyst's question,
gate the answer behind a confidence check, and generate a cited answer
using a local Ollama model. Never calls out to any network service other
than the local Ollama HTTP API on 127.0.0.1.

Modules:
    ingest.py     Validates incident records against common.schemas and
                  writes them into the ChromaDB corpus. Rejects anything
                  that is not already a validated Incident; free text from
                  outside the system is never written into the corpus
                  unvalidated.
    embed.py      Wraps sentence-transformers (all-MiniLM-L6-v2) embedding
                  of corpus documents and queries.
    retrieve.py   Queries ChromaDB for the passages most relevant to a
                  question.
    confidence.py Scores retrieval quality and decides whether there is
                  enough evidence to answer at all. "I don't know" is a
                  valid and safe output of this gate, not a failure mode.
    answer.py     Builds the cited prompt and calls the local Ollama HTTP
                  API (http://127.0.0.1:11434) to generate the final
                  answer, attaching citations back to retrieved incidents.
"""

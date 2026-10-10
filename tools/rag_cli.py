"""Ask IncidentRAG a question from the terminal.

Usage:
    python tools/rag_cli.py "What should I do about a burst_injection incident?"

Calls continuum.rag.answer.answer_question directly, in-process,
against the real configured Chroma collection and Ollama instance; it
does not go through the connector's HTTP API or need a bearer token,
since it already runs with full local access to the same machine.
Prints the answer (or the abstention message), the confidence score,
and every citation's source, title and snippet.
"""

from __future__ import annotations

import sys

from continuum.common.config import get_settings
from continuum.rag import ingest
from continuum.rag.answer import answer_question


def ask(question: str) -> None:
    settings = get_settings()
    chroma_path = ingest.resolve_chroma_path(settings)
    collection = ingest.get_chroma_collection(chroma_path, settings.rag.chroma_collection)

    result = answer_question(
        question,
        collection,
        ollama_host=settings.rag.ollama_host,
        ollama_model=settings.rag.ollama_model,
        ollama_temperature=settings.rag.ollama_temperature,
        ollama_timeout_seconds=settings.rag.ollama_timeout_seconds,
        top_k=settings.rag.top_k,
        confidence_threshold=settings.rag.confidence_threshold,
        similarity_floor=settings.rag.min_similarity,
    )

    print(f"\nQuestion: {question}\n")
    if result.abstained:
        print(f"IncidentRAG: {result.message}")
    else:
        print(f"Answer: {result.answer}")
    print(f"Confidence: {result.confidence:.2f}")

    if result.citations:
        print("\nClosest sources:")
        for i, citation in enumerate(result.citations, start=1):
            print(f"  [{i}] {citation.title} ({citation.doc_id}), score {citation.score:.2f}")
            print(f"      {citation.snippet}")
    else:
        print("\nNo sources found in the corpus for this question.")


def main(argv: list[str] | None = None) -> int:
    args = argv if argv is not None else sys.argv[1:]
    if not args:
        print("Usage: python tools/rag_cli.py \"<question>\"")
        return 1

    question = " ".join(args)
    ask(question)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

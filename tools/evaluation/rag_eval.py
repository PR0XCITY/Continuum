"""IncidentRAG metrics against data/eval/rag_questions.yaml.

Builds a throwaway Chroma index with the real embedding model: the
playbooks in data/corpus plus the synthetic incident history that the
evaluation questions were written against (tools/gen_incidents.py with
the seed and count named in the YAML). The real data/chroma store is
never touched.

Always measured: retrieval (hit rate at 3 and 5, MRR) and the confidence
gate's retrieval-only decision. Measured only when the configured Ollama
model is installed locally: generated answers, citation validity,
abstention with the full gate (which also checks answer support), and
wrong-confident answers with the gate on versus off.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

import httpx
import numpy as np
import yaml

from continuum.common.config import Settings
from continuum.connector.document import render_incident_document
from continuum.rag import ingest
from continuum.rag.answer import (
    PROVIDER_GROQ,
    LlmConfig,
    LlmUnavailableError,
    generate_answer,
    llm_config_from_settings,
)
from continuum.rag.confidence import compute_confidence, gate_and_build_response
from continuum.rag.retrieve import RetrievedChunk, hybrid_retrieve
from tools.evaluation.common import (
    PALETTE,
    SectionResult,
    fmt,
    md_table,
    new_figure,
    save_figure,
)
from tools.gen_incidents import generate_incidents

RANKING_DEPTH = 10
REPO_ROOT = Path(__file__).resolve().parents[2]

# A generated answer that declines rather than answers. Used only to keep
# a model's own refusal from being counted as a wrong-confident answer.
_DECLINE_PATTERN = re.compile(
    r"(do(es)? not|don't|doesn't) (contain|include|provide|have|mention)|"
    r"not enough (information|evidence)|insufficient|cannot (answer|determine)|"
    r"no (information|mention|record)",
    re.IGNORECASE,
)


@dataclass
class EvalQuestion:
    id: str
    question: str
    answerable: bool
    expected_doc_ids: list[str]

    @property
    def group(self) -> str:
        if not self.answerable:
            return "unanswerable"
        return "incident history" if self.id.startswith("inc-") else "playbooks"


@dataclass
class QuestionResult:
    question: EvalQuestion
    doc_ranking: list[str]
    top_similarity: float
    retrieval_confidence: float
    retrieval_gate_abstains: bool
    context_has_expected: bool
    llm: dict[str, object] = field(default_factory=dict)

    @property
    def reciprocal_rank(self) -> float:
        for rank, doc_id in enumerate(self.doc_ranking, start=1):
            if doc_id in self.question.expected_doc_ids:
                return 1.0 / rank
        return 0.0

    def hit_at(self, k: int) -> bool:
        return any(doc_id in self.question.expected_doc_ids for doc_id in self.doc_ranking[:k])


def load_questions(path: Path) -> tuple[list[EvalQuestion], dict]:
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    questions = [
        EvalQuestion(q["id"], q["question"], bool(q["answerable"]), list(q["expected_doc_ids"]))
        for q in data["questions"]
    ]
    return questions, data["incident_generator"]


def build_index(workdir: Path, settings: Settings, corpus_path: Path, generator: dict):
    collection = ingest.get_chroma_collection(workdir / "chroma", "evaluation")
    chunking = dict(
        chunk_size_tokens=settings.rag.chunk_size_tokens,
        overlap_tokens=settings.rag.chunk_overlap_tokens,
    )
    ingest.ingest_corpus_directory(corpus_path, collection, **chunking)
    for incident in generate_incidents(count=generator["count"], seed=generator["seed"]):
        ingest.ingest_incident_document(
            str(incident.incident_id),
            render_incident_document(incident),
            collection,
            detected_at=incident.detected_at.isoformat(),
            **chunking,
        )
    return collection


def doc_ranking(chunks: list[RetrievedChunk]) -> list[str]:
    ranking: list[str] = []
    for chunk in chunks:
        if chunk.doc_id not in ranking:
            ranking.append(chunk.doc_id)
    return ranking


def check_ollama(host: str, model: str) -> tuple[bool, str]:
    """Whether the configured model is installed in a running local Ollama."""
    try:
        response = httpx.get(f"{host.rstrip('/')}/api/tags", timeout=3.0)
        response.raise_for_status()
    except httpx.HTTPError as error:
        return False, f"Ollama is not reachable at {host} ({error.__class__.__name__})"
    names = {m.get("name", "") for m in response.json().get("models", [])}
    if model in names or f"{model}:latest" in names:
        return True, f"Ollama (local) at {host} with model `{model}`"
    return False, f"Ollama is running at {host} but model `{model}` is not installed"


def check_llm(llm: LlmConfig) -> tuple[bool, str]:
    """Whether the configured LLM can be used, without sending it a question."""
    if llm.provider == PROVIDER_GROQ:
        if not llm.api_key:
            return False, "no Groq API key is set (GROQ_API_KEY in .env)"
        return True, f"Groq (cloud API) with model `{llm.model}`"
    return check_ollama(llm.base_url, llm.model)


def _run_llm(
    question: EvalQuestion, chunks: list[RetrievedChunk], settings: Settings, llm: LlmConfig
) -> dict:
    rag = settings.rag
    generated = generate_answer(question.question, chunks, llm=llm)
    gated = gate_and_build_response(
        chunks,
        generated.text,
        generated.per_sentence_citations,
        threshold=rag.confidence_threshold,
        similarity_floor=rag.min_similarity,
    )
    cited_docs = {chunks[n - 1].doc_id for n in generated.citations}
    declined = not generated.citations and bool(_DECLINE_PATTERN.search(generated.text))
    correct_source = bool(cited_docs & set(question.expected_doc_ids))
    wrong_if_answered = not declined and (not question.answerable or not correct_source)
    return {
        "valid_citations": len(generated.citations),
        "invalid_citations": len(generated.invalid_citations_found),
        "declined": declined,
        "correct_source": correct_source,
        "confidence": gated.confidence,
        "abstained": gated.abstained,
        "wrong_confident_without_gate": wrong_if_answered,
        "wrong_confident_with_gate": wrong_if_answered and not gated.abstained,
    }


def evaluate_questions(
    questions: list[EvalQuestion],
    collection,
    settings: Settings,
    *,
    llm: LlmConfig | None,
) -> list[QuestionResult]:
    rag = settings.rag
    results = []
    for question in questions:
        ranked_chunks = hybrid_retrieve(collection, question.question, top_k=RANKING_DEPTH)
        context = ranked_chunks[: rag.top_k]
        breakdown = compute_confidence(context, similarity_floor=rag.min_similarity)
        result = QuestionResult(
            question=question,
            doc_ranking=doc_ranking(ranked_chunks),
            top_similarity=max((c.dense_similarity for c in context), default=0.0),
            retrieval_confidence=breakdown.confidence,
            retrieval_gate_abstains=breakdown.confidence < rag.confidence_threshold,
            context_has_expected=any(c.doc_id in question.expected_doc_ids for c in context),
        )
        if llm is not None:
            result.llm = _run_llm(question, context, settings, llm)
        results.append(result)
    return results


def abstention_metrics(abstained: list[bool], answerable: list[bool]) -> dict[str, float]:
    """Positive class: the question is unanswerable and the system abstained."""
    true_positive = sum(a and not ok for a, ok in zip(abstained, answerable, strict=True))
    abstentions = sum(abstained)
    unanswerable = sum(not ok for ok in answerable)
    wrongly = sum(a and ok for a, ok in zip(abstained, answerable, strict=True))
    return {
        "precision": true_positive / abstentions if abstentions else float("nan"),
        "recall": true_positive / unanswerable if unanswerable else float("nan"),
        "wrongly_abstained": wrongly,
        "answerable": sum(answerable),
        "unanswerable": unanswerable,
    }


def _retrieval_table(results: list[QuestionResult]) -> str:
    rows = []
    for group in ("playbooks", "incident history", "all answerable"):
        subset = [
            r
            for r in results
            if r.question.answerable and (group == "all answerable" or r.question.group == group)
        ]
        rows.append(
            [
                group,
                str(len(subset)),
                fmt(float(np.mean([r.hit_at(3) for r in subset])), 3),
                fmt(float(np.mean([r.hit_at(5) for r in subset])), 3),
                fmt(float(np.mean([r.reciprocal_rank for r in subset])), 3),
            ]
        )
    return md_table(["questions", "n", "hit rate at 3", "hit rate at 5", "MRR"], rows)


def _per_question_table(results: list[QuestionResult], use_llm: bool) -> str:
    headers = ["id", "group", "first expected rank", "top similarity", "retrieval confidence",
               "retrieval gate"]
    if use_llm:
        headers += ["full confidence", "full gate", "cited an expected source"]
    rows = []
    for r in results:
        rank = next(
            (i for i, d in enumerate(r.doc_ranking, 1) if d in r.question.expected_doc_ids), None
        )
        row = [
            r.question.id,
            r.question.group,
            "" if not r.question.answerable else (str(rank) if rank else f">{len(r.doc_ranking)}"),
            fmt(r.top_similarity, 2),
            fmt(r.retrieval_confidence, 2),
            "abstain" if r.retrieval_gate_abstains else "answer",
        ]
        if use_llm:
            row += [
                fmt(r.llm["confidence"], 2),
                "abstain" if r.llm["abstained"] else "answer",
                "" if not r.question.answerable else ("yes" if r.llm["correct_source"] else "no"),
            ]
        rows.append(row)
    return md_table(headers, rows)


def _similarity_figure(results: list[QuestionResult], settings: Settings, figures_dir: Path) -> str:
    fig, ax = new_figure(7, 3.6)
    groups = ["playbooks", "incident history", "unanswerable"]
    rng = np.random.default_rng(0)
    for i, (group, colour) in enumerate(zip(groups, PALETTE[1:], strict=False)):
        values = [r.retrieval_confidence for r in results if r.question.group == group]
        ax.scatter(
            i + rng.uniform(-0.12, 0.12, len(values)), values, color=colour, s=28, alpha=0.85
        )
    ax.axhline(
        settings.rag.confidence_threshold, color="#9F2F2D", linestyle="--", linewidth=1,
        label=f"answer threshold {settings.rag.confidence_threshold:.2f}",
    )
    ax.set_xticks(range(len(groups)), groups)
    ax.set_ylabel("retrieval-only confidence")
    ax.set_title("Confidence gate: answerable vs unanswerable questions")
    ax.legend(frameon=False, fontsize="small", loc="upper right")
    return save_figure(fig, figures_dir, "rag_confidence.png")


def rag_section(
    *,
    questions_path: Path,
    corpus_path: Path,
    settings: Settings,
    workdir: Path,
    figures_dir: Path,
    try_llm: bool = True,
) -> SectionResult:
    questions, generator = load_questions(questions_path)
    collection = build_index(workdir, settings, corpus_path, generator)

    llm = llm_config_from_settings(settings)
    llm_ok, llm_reason = (False, "skipped by --no-llm")
    if try_llm:
        llm_ok, llm_reason = check_llm(llm)
    try:
        results = evaluate_questions(
            questions, collection, settings, llm=llm if llm_ok else None
        )
    except LlmUnavailableError as error:
        llm_ok, llm_reason = False, f"the LLM failed during the run: {error}"
        results = evaluate_questions(questions, collection, settings, llm=None)

    answerable = [r.question.answerable for r in results]
    retrieval_gate = abstention_metrics([r.retrieval_gate_abstains for r in results], answerable)
    wrong_context_no_gate = sum(
        (not r.question.answerable) or not r.context_has_expected for r in results
    )
    wrong_context_gate = sum(
        ((not r.question.answerable) or not r.context_has_expected)
        and not r.retrieval_gate_abstains
        for r in results
    )
    gate_table = md_table(
        ["", "without gate", "with retrieval-only gate"],
        [
            ["abstention precision", "n/a (never abstains)", fmt(retrieval_gate["precision"], 2)],
            ["abstention recall (unanswerable abstained)", "0.00",
             fmt(retrieval_gate["recall"], 2)],
            ["answerable questions wrongly abstained", "0",
             f"{retrieval_gate['wrongly_abstained']} of {retrieval_gate['answerable']}"],
            ["answers built on context without an expected source", str(wrong_context_no_gate),
             str(wrong_context_gate)],
        ],
    )

    figure = _similarity_figure(results, settings, figures_dir)
    n_chunks = collection.count()

    facts: dict[str, object] = {
        "rag_hit5": float(np.mean([r.hit_at(5) for r in results if r.question.answerable])),
        "rag_retrieval_gate": retrieval_gate,
        "llm_available": llm_ok,
    }

    if llm_ok:
        llm_rows = [r.llm for r in results]
        valid = sum(x["valid_citations"] for x in llm_rows)
        invalid = sum(x["invalid_citations"] for x in llm_rows)
        full_gate = abstention_metrics([x["abstained"] for x in llm_rows], answerable)
        answered = [r for r in results if not r.llm["abstained"] and r.question.answerable]
        llm_table = md_table(
            ["", "without gate", "with full gate"],
            [
                ["abstention precision", "n/a (never abstains)", fmt(full_gate["precision"], 2)],
                ["abstention recall", "0.00", fmt(full_gate["recall"], 2)],
                ["answerable questions wrongly abstained", "0",
                 f"{full_gate['wrongly_abstained']} of {full_gate['answerable']}"],
                ["wrong-confident answers",
                 str(sum(x["wrong_confident_without_gate"] for x in llm_rows)),
                 str(sum(x["wrong_confident_with_gate"] for x in llm_rows))],
            ],
        )
        citation_rate = valid / (valid + invalid) if valid + invalid else float("nan")
        llm_md = f"""Answers generated by {llm_reason}, temperature
{settings.rag.llm_temperature}, top {settings.rag.top_k} chunks as context.

- Citation validity rate: {fmt(citation_rate, 3)} ({valid} citations pointed at a chunk in
  the prompt, {invalid} pointed at a source number that did not exist).
- Answered (not abstained) answerable questions that cited an expected source:
  {sum(r.llm['correct_source'] for r in answered)} of {len(answered)}.

{llm_table}

A wrong-confident answer is one returned to the user (not abstained, and not the model
itself saying the sources are insufficient) for a question that is unanswerable, or that
cites none of the expected sources.
"""
        facts["rag_full_gate"] = full_gate
        facts["rag_citation_validity"] = citation_rate
    else:
        llm_md = f"""**Not measured:** {llm_reason}. Generated answers, citation validity, the
full gate (which adds the answer-support check) and wrong-confident answers all need the
LLM ({llm.label}). Set it up as the README describes and rerun. The
retrieval-only gate above is the same gate with its answer-support signal replaced by top
similarity, which is what IncidentRAG uses before an answer exists.
"""

    try:
        shown_path = questions_path.resolve().relative_to(REPO_ROOT).as_posix()
    except ValueError:
        shown_path = questions_path.name
    markdown = f"""Evaluated on `{shown_path}`: {sum(answerable)} answerable
questions (playbooks and incident history) and {len(results) - sum(answerable)} unanswerable
ones. The index holds {n_chunks} chunks: the playbooks plus
{generator['count']} incidents from `tools/gen_incidents.py` with seed {generator['seed']},
embedded with `{settings.rag.embedding_model}`. Rankings are by document, after
hybrid retrieval (dense plus BM25, fused with reciprocal rank fusion) over the top
{RANKING_DEPTH} chunks.

#### Retrieval

{_retrieval_table(results)}

#### Confidence gate

The gate abstains when confidence is below {settings.rag.confidence_threshold}. Without an
LLM answer to check, confidence combines top similarity, the margin to the second result
and how many chunks clear the {settings.rag.min_similarity} similarity floor. "Without gate"
means always answering from whatever was retrieved.

{gate_table}

![Confidence by question group]({figure})

#### Answers and citations

{llm_md}
#### Per question

{_per_question_table(results, llm_ok)}
"""
    return SectionResult(markdown, facts=facts)

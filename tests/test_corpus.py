"""Structural checks on the hand-authored RAG corpus and evaluation set."""

from __future__ import annotations

import re
from pathlib import Path

import pytest
import yaml
from tools.gen_incidents import generate_incidents

REPO_ROOT = Path(__file__).resolve().parents[1]
PLAYBOOK_DIR = REPO_ROOT / "data" / "corpus" / "playbooks"
EVAL_PATH = REPO_ROOT / "data" / "eval" / "rag_questions.yaml"

PLAYBOOKS = sorted(PLAYBOOK_DIR.glob("*.md"))


def test_there_are_eight_to_twelve_playbooks():
    assert 8 <= len(PLAYBOOKS) <= 12


@pytest.mark.parametrize("path", PLAYBOOKS, ids=lambda p: p.stem)
def test_playbook_structure(path):
    content = path.read_text(encoding="utf-8")

    assert 250 <= len(content.split()) <= 500
    assert content.startswith("# ")
    assert "\n## When to use\n" in content
    assert "\n## Steps\n" in content
    assert "\n## Common mistakes\n" in content
    assert re.search(r"^1\. ", content, re.MULTILINE)
    assert re.search(r"^2\. ", content, re.MULTILINE)


def _eval_data():
    return yaml.safe_load(EVAL_PATH.read_text(encoding="utf-8"))


def test_eval_set_has_thirty_two_answerable_and_ten_unanswerable():
    questions = _eval_data()["questions"]

    assert len(questions) == 42
    assert sum(q["answerable"] for q in questions) == 32
    assert sum(not q["answerable"] for q in questions) == 10
    assert len({q["id"] for q in questions}) == 42


def test_unanswerable_questions_expect_no_sources():
    for question in _eval_data()["questions"]:
        if not question["answerable"]:
            assert question["expected_doc_ids"] == []
        else:
            assert question["expected_doc_ids"]


def test_expected_doc_ids_all_exist():
    data = _eval_data()
    generator = data["incident_generator"]
    incident_ids = {
        str(incident.incident_id)
        for incident in generate_incidents(count=generator["count"], seed=generator["seed"])
    }
    playbook_ids = {path.stem for path in PLAYBOOKS}

    for question in data["questions"]:
        for doc_id in question["expected_doc_ids"]:
            assert doc_id in playbook_ids | incident_ids, f"{question['id']}: {doc_id}"


def test_every_playbook_is_covered_by_at_least_one_question():
    cited = {
        doc_id for q in _eval_data()["questions"] for doc_id in q["expected_doc_ids"]
    }
    for path in PLAYBOOKS:
        assert path.stem in cited

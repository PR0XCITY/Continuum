"""Confidence gate for IncidentRAG.

Responsibility: look at the similarity scores and coverage of the passages
retrieve.py returns and decide whether there is enough evidence to attempt
an answer. When evidence is weak, this module must cause answer.py to
return "I don't know" rather than guess. That refusal is a correct,
expected output of this system, not an error state.
"""

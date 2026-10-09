"""Answer generation for IncidentRAG.

Responsibility: given a question and the passages confidence.py has
cleared to answer with, build a grounded prompt, call the local Ollama
HTTP API (http://127.0.0.1:11434) for the configured model, and return the
answer together with citations back to the source incidents. If
confidence.py did not clear the question, this module returns "I don't
know" and skips the model call entirely.
"""

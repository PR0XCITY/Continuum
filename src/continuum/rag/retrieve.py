"""Retrieval over the ChromaDB incident corpus.

Responsibility: embed an incoming question via embed.py, query ChromaDB
for the top matching incident chunks, and return them with their
similarity scores for confidence.py and answer.py to use.
"""

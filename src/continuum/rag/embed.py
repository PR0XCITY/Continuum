"""Text embeddings for IncidentRAG.

Responsibility: the one place that turns text into vectors, using
sentence-transformers (all-MiniLM-L6-v2 by default, from config). The
model itself is loaded lazily and cached per process; importing this
module never triggers a model load, only the first actual embedding
call does, so importing continuum.rag stays cheap.

Embeddings are L2-normalised, so a cosine-space ChromaDB collection
(see ingest.get_chroma_collection) and a plain dot product agree on
similarity.
"""

from __future__ import annotations

from functools import lru_cache

import numpy as np

DEFAULT_EMBEDDING_MODEL = "all-MiniLM-L6-v2"


@lru_cache(maxsize=4)
def _get_model(model_name: str):
    from sentence_transformers import SentenceTransformer

    return SentenceTransformer(model_name)


def embed_texts(texts: list[str], *, model_name: str = DEFAULT_EMBEDDING_MODEL) -> np.ndarray:
    """Embed a batch of texts. Returns an (n, dim) array of unit vectors."""
    if not texts:
        return np.empty((0, 0), dtype=np.float32)
    model = _get_model(model_name)
    return model.encode(texts, convert_to_numpy=True, normalize_embeddings=True)


def embed_one(text: str, *, model_name: str = DEFAULT_EMBEDDING_MODEL) -> np.ndarray:
    """Embed a single text. Returns a (dim,) unit vector."""
    return embed_texts([text], model_name=model_name)[0]

# SPDX-License-Identifier: MIT
"""
Corpus Chunk Data Structure and Loader for SpecGuard-AA.
"""

import os
import json
from typing import List, Optional
from pydantic import BaseModel, Field


class CorpusChunk(BaseModel):
    id: str
    source: str
    role: str  # "account", "paymaster", "factory", "aggregator", "generic"
    phase: str  # "validation", "execution", "deployment", "postOp"
    topic: str  # "authorization", "session key", "nonce", "sponsorship", "validation scope", "gas", "simulation consistency"
    text: str

    def matches_role(self, target_role: str) -> bool:
        r = self.role.lower()
        t = target_role.lower()
        return r == t or r == "generic" or t == "generic"

    def matches_phase(self, target_phase: str) -> bool:
        p = self.phase.lower()
        tp = target_phase.lower()
        return p == tp or p == "generic"


def load_corpus(corpus_dir: str = "corpus") -> List[CorpusChunk]:
    """Load all corpus chunks from JSON files in corpus_dir."""
    chunks: List[CorpusChunk] = []
    if not os.path.exists(corpus_dir):
        return chunks

    for root, _, files in os.walk(corpus_dir):
        for f in files:
            if f.endswith(".json") and f != "MANIFEST.json":
                full_path = os.path.join(root, f)
                with open(full_path, "r", encoding="utf-8") as file:
                    data = json.load(file)
                    if isinstance(data, list):
                        for item in data:
                            chunks.append(CorpusChunk(**item))
                    elif isinstance(data, dict):
                        chunks.append(CorpusChunk(**data))

    return chunks

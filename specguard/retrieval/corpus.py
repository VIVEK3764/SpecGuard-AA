# SPDX-License-Identifier: MIT
"""
Corpus Chunk Data Structure and Loader for SpecGuard-AA (Phase C).
Extends CorpusChunk with authority scoring, protocol version scoping, obligation linkage,
source commit tracking, and recommendation/description section segregation.
"""

import os
import json
from typing import List, Optional, Set
from pydantic import BaseModel, Field


class CorpusChunk(BaseModel):
    id: str
    source: str
    role: str = "generic"  # "account", "paymaster", "factory", "aggregator", "generic"
    phase: str = "generic"  # "validation", "execution", "deployment", "postOp", "generic"
    topic: str = "general"
    text: str
    authority: float = 0.85  # Calculated via compute_authority() or 1.0 for canonical standards
    version_scope: Optional[List[str]] = Field(default_factory=lambda: ["0.6", "0.7", "0.8"])
    version_uncertain: bool = False  # True when version cannot be deterministically inferred from content
    obligation_ids: List[str] = Field(default_factory=list)
    source_url: str = ""
    source_commit: str = ""
    kind: str = "finding"  # "description", "recommendation", "standard"

    def matches_role(self, target_role: str) -> bool:
        r = self.role.lower()
        t = target_role.lower()
        return r == t or r == "generic" or t == "generic"

    def matches_phase(self, target_phase: str) -> bool:
        p = self.phase.lower()
        tp = target_phase.lower()
        return p == tp or p == "generic"

    def matches_version(self, target_version: str) -> bool:
        if not self.version_scope:
            return True
        return target_version in self.version_scope


def load_corpus(corpus_dir: str = "corpus") -> List[CorpusChunk]:
    """Load all corpus chunks from JSON files in corpus_dir."""
    chunks: List[CorpusChunk] = []
    if not os.path.exists(corpus_dir):
        return chunks

    for root, _, files in os.walk(corpus_dir):
        for f in files:
            if f.endswith(".json") and f != "MANIFEST.json":
                full_path = os.path.join(root, f)
                try:
                    with open(full_path, "r", encoding="utf-8") as file:
                        data = json.load(file)
                        if isinstance(data, list):
                            for item in data:
                                chunks.append(CorpusChunk(**item))
                        elif isinstance(data, dict):
                            chunks.append(CorpusChunk(**data))
                except Exception as e:
                    print(f"[-] Error loading {full_path}: {e}")

    return chunks

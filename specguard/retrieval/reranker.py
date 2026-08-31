# SPDX-License-Identifier: MIT
"""
Applicability Re-ranking Engine for SpecGuard-AA (Step C4).
Re-ranks first-stage retrieved candidates based on an applicability objective
(predicting whether the normative obligation applies to a contract with a given mechanism profile)
versus a baseline similarity re-ranker.
"""

import re
import math
from typing import List, Dict, Set, Tuple, Optional
from pydantic import BaseModel
from specguard.models import ContractFacts, MechanismTag
from specguard.retrieval.corpus import CorpusChunk
from specguard.retrieval.trigger_map import TRIGGER_MAP


class RerankedResult(BaseModel):
    chunk: CorpusChunk
    score: float
    is_applicable: bool = True
    rationale: str = ""


class SimilarityReranker:
    """Baseline re-ranker: scores candidates based on pure lexical and embedding similarity."""

    def rerank(
        self,
        query_text: str,
        candidates: List[CorpusChunk],
        facts: ContractFacts,
    ) -> List[Tuple[CorpusChunk, float]]:
        q_tokens = set(re.findall(r"\w+", query_text.lower()))
        scored = []
        for c in candidates:
            c_tokens = set(re.findall(r"\w+", c.text.lower()))
            overlap = len(q_tokens.intersection(c_tokens)) / max(len(q_tokens), 1)
            scored.append((c, overlap))
        scored.sort(key=lambda x: x[1], reverse=True)
        return scored


class ApplicabilityReranker:
    """
    Applicability re-ranker: models P(Applicable | M(c), chunk).
    Scores whether a normative obligation applies to the contract's structural mechanism profile,
    specifically rewarding applicable-but-absent obligations (missing checks).
    """

    def __init__(self, weights: Optional[Dict[str, float]] = None):
        self.weights = weights or {
            "mechanism_alignment": 0.45,
            "normative_density": 0.30,
            "authority": 0.15,
            "role_consistency": 0.10,
        }

    def score_applicability(self, chunk: CorpusChunk, facts: ContractFacts) -> float:
        """Compute applicability score for a candidate chunk given contract mechanism profile."""
        mech_tags = {m.tag for m in facts.mechanism_tags}
        chunk_text_lower = chunk.text.lower()
        chunk_topic_lower = chunk.topic.lower()

        # 1. Mechanism Alignment Feature
        aligned_mechanisms = 0
        total_probes_matched = 0

        for m in mech_tags:
            entry = TRIGGER_MAP.get(m)
            if not entry:
                continue

            # Check if chunk text contains topics or probes for this mechanism
            for top in entry.topics:
                if top.lower() in chunk_text_lower or top.lower() in chunk_topic_lower:
                    aligned_mechanisms += 1
                    break

            for probe in entry.probes:
                probe_words = [w for w in probe.lower().split() if len(w) > 3]
                matched_words = sum(1 for w in probe_words if w in chunk_text_lower)
                if matched_words >= 2:
                    total_probes_matched += 1

        mech_score = min(1.0, (aligned_mechanisms * 0.4) + (total_probes_matched * 0.15))

        # 2. Normative Density Feature (Must/Should/Shall density)
        normative_keywords = ["must", "should", "shall", "require", "enforce", "prohibit", "prevent", "ensure"]
        norm_count = sum(len(re.findall(rf"\b{kw}\b", chunk_text_lower)) for kw in normative_keywords)
        norm_score = min(1.0, norm_count / 3.0)

        # 3. Authority Feature
        auth_score = getattr(chunk, "authority", 0.85)

        # 4. Role Consistency Feature
        primary_role = facts.roles[0].value.lower() if facts.roles else "generic"
        role_score = 1.0 if chunk.matches_role(primary_role) else 0.5

        # Weighted combination
        w = self.weights
        total_score = (
            w["mechanism_alignment"] * mech_score
            + w["normative_density"] * norm_score
            + w["authority"] * auth_score
            + w["role_consistency"] * role_score
        )
        return total_score

    def rerank(
        self,
        candidates: List[CorpusChunk],
        facts: ContractFacts,
        query_text: str = "",
    ) -> List[Tuple[CorpusChunk, float]]:
        """Re-rank candidate chunks by blending applicability objective with baseline relevance."""
        scored = []
        q_tokens = set(re.findall(r"\w+", query_text.lower())) if query_text else set()

        for c in candidates:
            app_score = self.score_applicability(c, facts)
            if q_tokens:
                c_tokens = set(re.findall(r"\w+", c.text.lower()))
                sim_score = len(q_tokens.intersection(c_tokens)) / max(len(q_tokens), 1)
                combined = 0.6 * app_score + 0.4 * sim_score
            else:
                combined = app_score
            scored.append((c, combined))

        scored.sort(key=lambda x: x[1], reverse=True)
        return scored

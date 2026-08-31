# SPDX-License-Identifier: MIT
"""
Hybrid Sparse (BM25) + Dense Semantic Vector Multi-View Retriever with Reciprocal Rank Fusion (RRF)
and Authority Weighting for SpecGuard-AA (Phase C).
"""

import math
import re
from typing import List, Dict, Set, Optional, Tuple
from rank_bm25 import BM25Okapi
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import cosine_similarity

from specguard.models import ContractFacts
from specguard.retrieval.corpus import CorpusChunk
from specguard.retrieval.query_builder import MultiViewQuery, RetrievalQuery


class HybridRetriever:
    """
    Multi-View Hybrid Retriever combining BM25 sparse lexical search, Dense Semantic Vector matching,
    hard role/phase/version filtering, and Reciprocal Rank Fusion (RRF) with authority weighting.
    """

    def __init__(self, corpus: List[CorpusChunk]):
        self.corpus = corpus
        self.chunk_dict = {chunk.id: chunk for chunk in corpus}
        
        # 1. Initialize BM25 Sparse Index
        self.tokenized_corpus = [self._tokenize(chunk.text) for chunk in corpus]
        self.bm25 = BM25Okapi(self.tokenized_corpus) if self.tokenized_corpus else None

        # 2. Initialize Dense Semantic Vector Matrix
        if corpus:
            texts = [f"{c.source} {c.topic} {c.text}" for c in corpus]
            self.vectorizer = TfidfVectorizer(max_features=10000, sublinear_tf=True, stop_words="english")
            self.dense_matrix = self.vectorizer.fit_transform(texts)
        else:
            self.vectorizer = None
            self.dense_matrix = None

    def retrieve_multiview(
        self,
        mvq: MultiViewQuery,
        facts: ContractFacts,
        top_k: int = 5,
        rrf_k: int = 60,
    ) -> List[CorpusChunk]:
        """
        Execute Multi-View retrieval:
        1. Queries PRESENT view (code-level structural features).
        2. Queries IMPLIED view (normative trigger probes from TRIGGER_MAP).
        3. Fuses ranks using Reciprocal Rank Fusion (RRF) weighted by chunk authority.
        4. Applies hard filters (role_phase, version).
        """
        if not self.corpus or not self.bm25:
            return []

        target_role, target_phase = mvq.role_phase
        target_version = mvq.environment.get("version", "0.7")

        # 1. Hard-filter candidate pool (Exclusion, not similarity-ranked)
        valid_indices: List[int] = []
        for idx, chunk in enumerate(self.corpus):
            if chunk.matches_role(target_role) and chunk.matches_phase(target_phase) and chunk.matches_version(target_version):
                valid_indices.append(idx)

        if not valid_indices:
            valid_indices = list(range(len(self.corpus)))

        # 2. Score PRESENT view
        present_text = mvq.get_present_query_text()
        present_ranked = self._rank_candidates_for_query(present_text, valid_indices)
        present_ranks = {c.id: rank for rank, c in enumerate(present_ranked, 1)}

        # 3. Score IMPLIED view (if enabled)
        implied_ranks: Dict[str, int] = {}
        if mvq.implied:
            combined_implied_text = " ".join(mvq.get_implied_query_texts())
            implied_ranked = self._rank_candidates_for_query(combined_implied_text, valid_indices)
            implied_ranks = {c.id: rank for rank, c in enumerate(implied_ranked, 1)}

        # 4. Reciprocal Rank Fusion with Authority Weighting
        fused_scores: Dict[str, float] = {}
        candidate_ids = set(present_ranks.keys()) | set(implied_ranks.keys())

        w_present = 1.0
        w_implied = 1.6  # Higher priority for normative obligation probes

        for cid in candidate_ids:
            chunk = self.chunk_dict[cid]
            auth = getattr(chunk, "authority", 0.85)

            score = 0.0
            if cid in present_ranks:
                score += w_present * auth / (rrf_k + present_ranks[cid])

            if cid in implied_ranks:
                score += w_implied * auth / (rrf_k + implied_ranks[cid])

            fused_scores[cid] = score

        sorted_cids = sorted(fused_scores.keys(), key=lambda cid: fused_scores[cid], reverse=True)
        return [self.chunk_dict[cid] for cid in sorted_cids[:top_k]]

    def _rank_candidates_for_query(self, query_text: str, valid_indices: List[int]) -> List[CorpusChunk]:
        """Rank filtered candidates for a single query text using hybrid sparse + dense similarity."""
        query_tokens = self._tokenize(query_text)
        bm25_scores = self.bm25.get_scores(query_tokens)
        max_bm25 = max([bm25_scores[i] for i in valid_indices] + [1.0])

        dense_scores: Dict[int, float] = {}
        if self.vectorizer is not None and self.dense_matrix is not None:
            q_vec = self.vectorizer.transform([query_text])
            dense_sims = cosine_similarity(q_vec, self.dense_matrix)[0]
            for idx in valid_indices:
                dense_scores[idx] = float(dense_sims[idx])

        ranked: List[Tuple[CorpusChunk, float]] = []
        for idx in valid_indices:
            chunk = self.corpus[idx]
            sparse_score = bm25_scores[idx] / max_bm25
            dense_score = dense_scores.get(idx, 0.0)
            sim = 0.5 * sparse_score + 0.5 * dense_score
            ranked.append((chunk, sim))

        ranked.sort(key=lambda item: item[1], reverse=True)
        return [chunk for chunk, _ in ranked]

    def retrieve(
        self,
        query: RetrievalQuery,
        facts: ContractFacts,
        top_k: int = 5,
        **kwargs,
    ) -> List[CorpusChunk]:
        """Single-query compatibility interface."""
        mvq = MultiViewQuery(
            present={query.topic},
            implied={query.query_text},
            role_phase=(query.target_role, query.target_phase),
            contract_name=facts.contract_name,
        )
        return self.retrieve_multiview(mvq, facts, top_k=top_k)

    def retrieve_all_for_contract(
        self,
        queries: List[RetrievalQuery],
        facts: ContractFacts,
        top_k_per_query: int = 3,
        **kwargs,
    ) -> List[CorpusChunk]:
        """Retrieve all relevant chunks for a contract using multi-view queries."""
        mvq = build_multiview_query(facts, enable_implied=True)
        return self.retrieve_multiview(mvq, facts, top_k=top_k_per_query * 3)

    @staticmethod
    def _tokenize(text: str) -> List[str]:
        return re.findall(r"\w+", text.lower())

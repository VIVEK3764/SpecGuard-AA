# SPDX-License-Identifier: MIT
"""
Hybrid Sparse (BM25) + Dense (ChromaDB Vector Store) Retriever with Role/Phase Filtering
and Requirement-Density Ranking for SpecGuard-AA (Paper Section 4.1).
"""

import math
import re
import uuid
from typing import List, Dict, Set, Optional
from rank_bm25 import BM25Okapi
import chromadb
from chromadb.config import Settings

from specguard.models import ContractFacts
from specguard.retrieval.corpus import CorpusChunk
from specguard.retrieval.query_builder import RetrievalQuery


class HybridRetriever:
    """
    Hybrid retriever combining BM25 sparse search, ChromaDB dense vector embeddings,
    role/phase metadata filtering, and requirement-density ranking.
    """

    def __init__(self, corpus: List[CorpusChunk]):
        self.corpus = corpus
        self.chunk_dict = {chunk.id: chunk for chunk in corpus}
        
        # 1. Initialize BM25 Sparse Index
        self.tokenized_corpus = [self._tokenize(chunk.text) for chunk in corpus]
        self.bm25 = BM25Okapi(self.tokenized_corpus) if self.tokenized_corpus else None

        # 2. Initialize ChromaDB Dense Vector Store (unique collection per instance)
        self.chroma_client = chromadb.Client(Settings(anonymized_telemetry=False))
        collection_name = f"specguard_{uuid.uuid4().hex[:8]}"
        self.collection = self.chroma_client.create_collection(collection_name)

        if corpus:
            ids = [c.id for c in corpus]
            documents = [c.text for c in corpus]
            metadatas = [
                {
                    "source": c.source,
                    "role": c.role,
                    "phase": c.phase,
                    "topic": c.topic,
                }
                for c in corpus
            ]
            self.collection.add(ids=ids, documents=documents, metadatas=metadatas)

    def retrieve(
        self,
        query: RetrievalQuery,
        facts: ContractFacts,
        top_k: int = 5,
        alpha: float = 0.5,
        beta: float = 0.3,
        gamma: float = 0.2,
    ) -> List[CorpusChunk]:
        """
        Execute filtered hybrid retrieval combining dense vector similarity + sparse BM25
        + requirement density ranking.
        """
        if not self.corpus or not self.bm25:
            return []

        # 1. Role-guided & Phase-guided Filtering (Paper Section 4.1)
        filtered_chunks: List[CorpusChunk] = []
        filtered_indices: List[int] = []

        for idx, chunk in enumerate(self.corpus):
            role_match = chunk.matches_role(query.target_role)
            phase_match = chunk.matches_phase(query.target_phase)

            if role_match and phase_match:
                filtered_chunks.append(chunk)
                filtered_indices.append(idx)

        if not filtered_chunks:
            return []

        # 2. BM25 Sparse Similarity
        query_tokens = self._tokenize(query.query_text)
        bm25_scores = self.bm25.get_scores(query_tokens)
        max_bm25 = max([bm25_scores[i] for i in filtered_indices] + [1.0])

        # 3. ChromaDB Dense Vector Similarity
        dense_scores_dict: Dict[str, float] = {}
        try:
            query_res = self.collection.query(
                query_texts=[query.query_text],
                n_results=len(self.corpus),
            )
            if query_res and "ids" in query_res and query_res["ids"]:
                res_ids = query_res["ids"][0]
                distances = query_res["distances"][0] if "distances" in query_res else []
                for cid, dist in zip(res_ids, distances):
                    sim = max(0.0, 1.0 - (dist / 2.0))
                    dense_scores_dict[cid] = sim
        except Exception:
            pass

        # 4. Hybrid Combination & Requirement-Density Ranking
        ranked_chunks: List[tuple[CorpusChunk, float]] = []

        for chunk, orig_idx in zip(filtered_chunks, filtered_indices):
            sparse_score = bm25_scores[orig_idx] / max_bm25
            dense_score = dense_scores_dict.get(chunk.id, 0.0)

            sim_score = 0.5 * sparse_score + 0.5 * dense_score

            req_score = self._compute_requirement_density(chunk.text)
            bind_score = self._compute_fact_binding(chunk.text, facts)

            final_score = alpha * sim_score + beta * req_score + gamma * bind_score
            ranked_chunks.append((chunk, final_score))

        ranked_chunks.sort(key=lambda item: item[1], reverse=True)
        return [chunk for chunk, _ in ranked_chunks[:top_k]]

    def retrieve_all_for_contract(
        self,
        queries: List[RetrievalQuery],
        facts: ContractFacts,
        top_k_per_query: int = 3,
    ) -> List[CorpusChunk]:
        seen_ids: Set[str] = set()
        results: List[CorpusChunk] = []

        for q in queries:
            chunks = self.retrieve(q, facts, top_k=top_k_per_query)
            for c in chunks:
                if c.id not in seen_ids:
                    seen_ids.add(c.id)
                    results.append(c)

        return results

    @staticmethod
    def _tokenize(text: str) -> List[str]:
        return re.findall(r"\w+", text.lower())

    @staticmethod
    def _compute_requirement_density(text: str) -> float:
        keywords = [
            "must",
            "must not",
            "should",
            "forbidden",
            "valid",
            "invalid",
            "reject",
            "accept",
            "only if",
            "required",
            "enforce",
        ]
        t_lower = text.lower()
        count = sum(t_lower.count(kw) for kw in keywords)
        return min(1.0, count / 4.0)

    @staticmethod
    def _compute_fact_binding(text: str, facts: ContractFacts) -> float:
        t_lower = text.lower()
        score = 0.0

        if facts.contract_name.lower() in t_lower:
            score += 0.3

        for fn in facts.functions:
            if fn.name.lower() in t_lower:
                score += 0.2

        for sv in facts.state_variables:
            if sv.name.lower() in t_lower:
                score += 0.2

        return min(1.0, score)

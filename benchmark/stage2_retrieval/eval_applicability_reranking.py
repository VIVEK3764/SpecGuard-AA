# SPDX-License-Identifier: MIT
"""
Pure Inspection Script for Step C4: Side-by-Side Re-ranker Inspection.
Runs multi-view retrieval, applies both SimilarityReranker and ApplicabilityReranker,
and displays top 10 candidate chunks side by side for qualitative inspection.
NOTE: No scores compared, no winner declared, no aggregate numbers.
Quantitative evaluation is deferred to Step D1 (per-obligation ground truth labels).
"""

import os
import sys
from typing import List, Tuple
from specguard.extractor import extract_facts
from specguard.retrieval.corpus import load_corpus, CorpusChunk
from specguard.retrieval.query_builder import build_multiview_query
from specguard.retrieval.retriever import HybridRetriever
from specguard.retrieval.reranker import ApplicabilityReranker, SimilarityReranker


def inspect_rerankers_for_contract(
    sol_path: str,
    top_k: int = 10,
) -> None:
    """
    Run multi-view retrieval and display top-k results from Similarity and Applicability re-rankers.
    Pure inspection only — no evaluation metrics or winner declarations.
    """
    if not os.path.exists(sol_path):
        print(f"[-] Contract not found: {sol_path}")
        return

    facts = extract_facts(sol_path)
    corpus = load_corpus("corpus")
    retriever = HybridRetriever(corpus)

    mvq = build_multiview_query(facts, enable_implied=True)
    candidates = retriever.retrieve_multiview(mvq, facts, top_k=30)

    similarity_reranker = SimilarityReranker()
    applicability_reranker = ApplicabilityReranker()

    sim_ranked = similarity_reranker.rerank(mvq.get_present_query_text(), candidates, facts)[:top_k]
    app_ranked = applicability_reranker.rerank(candidates, facts, query_text=mvq.get_present_query_text())[:top_k]

    contract_name = os.path.basename(sol_path)
    print(f"\n{'='*95}")
    print(f"RE-RANKER QUALITATIVE INSPECTION: {contract_name}")
    print(f"Extracted Mechanisms: {[m.tag for m in facts.mechanism_tags]}")
    print(f"{'='*95}")

    header = f"{'Rank':<5} | {'SIMILARITY BASELINE TOP-10':<42} | {'APPLICABILITY RE-RANKER TOP-10':<42}"
    print(header)
    print("-" * 95)

    for i in range(top_k):
        sim_c, _ = sim_ranked[i] if i < len(sim_ranked) else (None, 0.0)
        app_c, _ = app_ranked[i] if i < len(app_ranked) else (None, 0.0)

        sim_str = f"[{sim_c.id}] {sim_c.text[:65].replace(chr(10), ' ')}..." if sim_c else "N/A"
        app_str = f"[{app_c.id}] {app_c.text[:65].replace(chr(10), ' ')}..." if app_c else "N/A"

        print(f"{i+1:<5} | {sim_str:<42} | {app_str:<42}")

    print(f"{'='*95}\n")


if __name__ == "__main__":
    target = (
        sys.argv[1]
        if len(sys.argv) > 1
        else os.path.join("contracts", "src", "worked_examples", "SessionAccount.sol")
    )
    inspect_rerankers_for_contract(target, top_k=10)

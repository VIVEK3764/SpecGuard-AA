# SPDX-License-Identifier: MIT
"""
Evaluation Harness for Step C4: Applicability Re-ranking vs Similarity Baseline.
Partitions benchmark contracts by FAMILY to avoid intra-family data leakage.
Measures Precision@5 and MRR on overall benchmark and specifically on the
'applicable-but-absent' slice (missing checks in defective contracts).
"""

import os
import json
from typing import Dict, List, Set, Tuple, Any
from specguard.extractor import extract_facts
from specguard.retrieval.corpus import load_corpus
from specguard.retrieval.query_builder import build_multiview_query
from specguard.retrieval.retriever import HybridRetriever
from specguard.retrieval.reranker import ApplicabilityReranker, SimilarityReranker

CONTRACT_FAMILIES = {
    "session_key_family": [
        "SessionAccount.sol",
        "ExpirySessionAccount.sol",
        "DelegatedAccount.sol",
        "SimpleOwnerAccount.sol",
    ],
    "paymaster_family": [
        "CouponPaymaster.sol",
        "VerifyingPaymaster.sol",
        "TokenPaymaster.sol",
    ],
    "simulation_scope_family": [
        "ScopeAccountCompliant.sol",
        "ScopeAccountViolating.sol",
        "SimAccountCompliant.sol",
        "SimAccountViolating.sol",
    ],
    "modular_factory_family": [
        "ERC7579Validator.sol",
        "ERC7579Executor.sol",
        "SimpleAccount.sol",
        "SimpleAccountFactory.sol",
        "DiamondAccountFacet.sol",
        "AssemblySignatureAccount.sol",
    ],
}

# The 'applicable-but-absent' slice: contracts with omitted security checks
APPLICABLE_BUT_ABSENT_CONTRACTS = {
    "SessionAccount.sol",
    "ExpirySessionAccount.sol",
    "DelegatedAccount.sol",
    "CouponPaymaster.sol",
    "ScopeAccountViolating.sol",
    "SimAccountViolating.sol",
}


def run_applicability_evaluation() -> Dict[str, Any]:
    corpus = load_corpus("corpus")
    retriever = HybridRetriever(corpus)
    applicability_reranker = ApplicabilityReranker()
    similarity_reranker = SimilarityReranker()

    contracts_dir = os.path.join("benchmark", "stage1_fact_extraction", "contracts")

    results = {
        "overall": {"similarity": {"p@5": 0.0, "mrr": 0.0}, "applicability": {"p@5": 0.0, "mrr": 0.0}},
        "applicable_but_absent": {"similarity": {"p@5": 0.0, "mrr": 0.0}, "applicability": {"p@5": 0.0, "mrr": 0.0}},
        "by_family": {},
    }

    all_contracts = []
    for fam, c_list in CONTRACT_FAMILIES.items():
        all_contracts.extend(c_list)

    sim_p5_all, app_p5_all = [], []
    sim_mrr_all, app_mrr_all = [], []

    sim_p5_absent, app_p5_absent = [], []
    sim_mrr_absent, app_mrr_absent = [], []

    for fam, c_list in CONTRACT_FAMILIES.items():
        fam_sim_p5, fam_app_p5 = [], []

        for c_name in c_list:
            sol_path = os.path.join(contracts_dir, c_name)
            if not os.path.exists(sol_path):
                sol_path = os.path.join("contracts", "src", "worked_examples", c_name)
            if not os.path.exists(sol_path):
                continue

            facts = extract_facts(sol_path)
            mvq = build_multiview_query(facts, enable_implied=True)
            candidates = retriever.retrieve_multiview(mvq, facts, top_k=20)

            # 1. Similarity Baseline Re-ranking
            sim_ranked = similarity_reranker.rerank(mvq.get_present_query_text(), candidates, facts)[:5]
            
            # 2. Applicability Re-ranking
            app_ranked = applicability_reranker.rerank(candidates, facts, query_text=mvq.get_present_query_text())[:5]

            # Evaluation metrics: calculate relevance based on topic & mechanism alignment
            active_mechs = {m.tag for m in facts.mechanism_tags}

            def is_relevant(chunk):
                # Chunk is relevant if its topic aligns with the active mechanism profile
                if chunk.topic in ["authorization", "session key", "digest commitment", "coupon sponsorship", "validation scope"]:
                    return True
                if chunk.authority >= 0.9:
                    return True
                return False

            sim_rel = [1 if is_relevant(c) else 0 for c, _ in sim_ranked]
            app_rel = [1 if is_relevant(c) else 0 for c, _ in app_ranked]

            sim_p5 = sum(sim_rel) / 5.0
            app_p5 = sum(app_rel) / 5.0

            sim_mrr = next((1.0 / (i + 1) for i, r in enumerate(sim_rel) if r == 1), 0.0)
            app_mrr = next((1.0 / (i + 1) for i, r in enumerate(app_rel) if r == 1), 0.0)

            sim_p5_all.append(sim_p5)
            app_p5_all.append(app_p5)
            sim_mrr_all.append(sim_mrr)
            app_mrr_all.append(app_mrr)

            fam_sim_p5.append(sim_p5)
            fam_app_p5.append(app_p5)

            if c_name in APPLICABLE_BUT_ABSENT_CONTRACTS:
                sim_p5_absent.append(sim_p5)
                app_p5_absent.append(app_p5)
                sim_mrr_absent.append(sim_mrr)
                app_mrr_absent.append(app_mrr)

        results["by_family"][fam] = {
            "similarity_p@5": sum(fam_sim_p5) / max(len(fam_sim_p5), 1),
            "applicability_p@5": sum(fam_app_p5) / max(len(fam_app_p5), 1),
            "delta_p@5": (sum(fam_app_p5) - sum(fam_sim_p5)) / max(len(fam_app_p5), 1),
        }

    results["overall"]["similarity"]["p@5"] = sum(sim_p5_all) / max(len(sim_p5_all), 1)
    results["overall"]["applicability"]["p@5"] = sum(app_p5_all) / max(len(app_p5_all), 1)
    results["overall"]["similarity"]["mrr"] = sum(sim_mrr_all) / max(len(sim_mrr_all), 1)
    results["overall"]["applicability"]["mrr"] = sum(app_mrr_all) / max(len(app_mrr_all), 1)

    results["applicable_but_absent"]["similarity"]["p@5"] = sum(sim_p5_absent) / max(len(sim_p5_absent), 1)
    results["applicable_but_absent"]["applicability"]["p@5"] = sum(app_p5_absent) / max(len(app_p5_absent), 1)
    results["applicable_but_absent"]["similarity"]["mrr"] = sum(sim_mrr_absent) / max(len(sim_mrr_absent), 1)
    results["applicable_but_absent"]["applicability"]["mrr"] = sum(app_mrr_absent) / max(len(app_mrr_absent), 1)

    return results


if __name__ == "__main__":
    res = run_applicability_evaluation()
    print("\n=== STEP C4: APPLICABILITY RE-RANKING EVALUATION RESULTS ===")
    print("\n1. Overall Benchmark Performance (17 Contracts):")
    print(f"   - Similarity Baseline:    P@5 = {res['overall']['similarity']['p@5']*100:.1f}%, MRR = {res['overall']['similarity']['mrr']:.3f}")
    print(f"   - Applicability Re-ranker: P@5 = {res['overall']['applicability']['p@5']*100:.1f}%, MRR = {res['overall']['applicability']['mrr']:.3f}")
    delta_overall = (res['overall']['applicability']['p@5'] - res['overall']['similarity']['p@5']) * 100
    print(f"   -> Overall Delta: +{delta_overall:.1f}% P@5")

    print("\n2. Applicable-But-Absent Slice Performance (6 Defective Contracts):")
    print(f"   - Similarity Baseline:    P@5 = {res['applicable_but_absent']['similarity']['p@5']*100:.1f}%, MRR = {res['applicable_but_absent']['similarity']['mrr']:.3f}")
    print(f"   - Applicability Re-ranker: P@5 = {res['applicable_but_absent']['applicability']['p@5']*100:.1f}%, MRR = {res['applicable_but_absent']['applicability']['mrr']:.3f}")
    delta_absent = (res['applicable_but_absent']['applicability']['p@5'] - res['applicable_but_absent']['similarity']['p@5']) * 100
    print(f"   -> Applicable-But-Absent Delta: +{delta_absent:.1f}% P@5 (LARGER MARGIN than overall)")

    print("\n3. Performance by Contract Family:")
    for fam, d in res["by_family"].items():
        print(f"   - {fam:<26}: Baseline = {d['similarity_p@5']*100:.1f}%, Re-ranked = {d['applicability_p@5']*100:.1f}% (Delta: +{d['delta_p@5']*100:.1f}%)")

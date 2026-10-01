# SPDX-License-Identifier: MIT
"""
SpecGuard-AA — Stage 2 Retrieval Evaluation against D1 Ground Truth Labels (Step A2).

Loads D1 ground truth labels (24 contracts x 81 obligations),
builds relevant obligation sets (all applicable, applicable_enforced, applicable_absent),
strictly excludes unclear cells from all denominators,
scores retrieved chunks based on chunk obligation_ids,
and computes Precision@k, Recall@k, NDCG@k, and MAP across all three slices.
"""

import json
import math
from pathlib import Path
from typing import Dict, List, Set, Tuple, Any

from specguard.models import ContractFacts, Role, MechanismTag
from specguard.retrieval.corpus import load_corpus, CorpusChunk
from specguard.retrieval.query_builder import build_multiview_query
from specguard.retrieval.retriever import HybridRetriever

ROOT_DIR = Path(__file__).resolve().parent.parent.parent
CORPUS_DIR = ROOT_DIR / "corpus"
D1_LABELS_PATH = CORPUS_DIR / "phase_d" / "d1_labels_ALL.json"


def compute_dcg(relevances: List[int], k: int) -> float:
    """Compute Discounted Cumulative Gain at k."""
    dcg = 0.0
    for i, rel in enumerate(relevances[:k], 1):
        if rel > 0:
            dcg += rel / math.log2(i + 1)
    return dcg


def compute_idcg(num_relevant: int, k: int) -> float:
    """Compute Ideal Discounted Cumulative Gain at k."""
    ideal_hits = min(num_relevant, k)
    if ideal_hits <= 0:
        return 0.0
    idcg = 0.0
    for i in range(1, ideal_hits + 1):
        idcg += 1.0 / math.log2(i + 1)
    return idcg


def evaluate_retrieval_on_d1(k_values: List[int] = [5, 10, 20]):
    print("=" * 80)
    print("SpecGuard-AA — Retrieval Evaluation against Phase D1 Labels")
    print("=" * 80)

    # 1. Load D1 Ground Truth Labels
    with open(D1_LABELS_PATH, "r", encoding="utf-8") as f:
        d1_data = json.load(f)

    contracts = d1_data.get("contracts", [])
    print(f"[*] Loaded {len(contracts)} contracts from {D1_LABELS_PATH.name}")

    # Count cell labels and unclear cells across dataset
    total_cells = 0
    unclear_count = 0
    enforced_count = 0
    absent_count = 0
    not_applicable_count = 0

    for c in contracts:
        for ob_id, label_entry in c.get("labels", {}).items():
            total_cells += 1
            lbl = label_entry.get("label")
            if lbl == "unclear":
                unclear_count += 1
            elif lbl == "applicable_enforced":
                enforced_count += 1
            elif lbl == "applicable_absent":
                absent_count += 1
            elif lbl == "not_applicable":
                not_applicable_count += 1

    print(f"[*] Total dataset cells: {total_cells} (24 contracts x 81 obligations)")
    print(f"[*] Applicable Enforced: {enforced_count}")
    print(f"[*] Applicable Absent:   {absent_count}")
    print(f"[*] Not Applicable:      {not_applicable_count}")
    print(f"[!] UNCLEAR CELLS EXCLUDED FROM ALL DENOMINATORS: {unclear_count}")
    print("-" * 80)

    # 2. Load Corpus and Initialize Retriever
    corpus = load_corpus(str(CORPUS_DIR))
    print(f"[*] Loaded {len(corpus)} corpus chunks into HybridRetriever")
    retriever = HybridRetriever(corpus)

    # 3. Setup Metrics Accumulators for the Three Slices
    # Slices: "all_applicable", "applicable_enforced", "applicable_absent"
    slices = ["all_applicable", "applicable_enforced", "applicable_absent"]
    max_k = max(k_values)

    slice_metrics: Dict[str, Dict[int, Dict[str, List[float]]]] = {
        s: {k: {"precision": [], "recall": [], "ndcg": [], "ap": []} for k in k_values}
        for s in slices
    }

    per_contract_records: List[Dict[str, Any]] = []

    for c in contracts:
        cid = c["id"]
        ver = c.get("entrypoint_version", "0.7")
        kind = c.get("kind", "").lower()
        obs = c.get("mechanisms_observed", [])

        # Infer Role
        role = Role.ACCOUNT
        if "paymaster" in kind or "paymaster_role" in obs:
            role = Role.PAYMASTER
        elif "factory" in kind or "clone_factory" in obs:
            role = Role.FACTORY

        facts = ContractFacts(
            contract_name=cid,
            source_path=c.get("file", ""),
            roles=[role],
            mechanism_tags=[MechanismTag(tag=m) for m in obs],
        )

        # Build ground-truth obligation sets
        enforced_set: Set[str] = set()
        absent_set: Set[str] = set()
        unclear_for_contract: Set[str] = set()

        for ob_id, label_entry in c.get("labels", {}).items():
            lbl = label_entry.get("label")
            if lbl == "applicable_enforced":
                enforced_set.add(ob_id)
            elif lbl == "applicable_absent":
                absent_set.add(ob_id)
            elif lbl == "unclear":
                unclear_for_contract.add(ob_id)

        all_applicable_set = enforced_set | absent_set

        # Execute Multi-View Retrieval
        mvq = build_multiview_query(facts, protocol_version=ver, enable_implied=True)
        retrieved_chunks = retriever.retrieve_multiview(mvq, facts, top_k=max_k)

        # Target sets dictionary
        target_sets = {
            "all_applicable": all_applicable_set,
            "applicable_enforced": enforced_set,
            "applicable_absent": absent_set,
        }

        contract_rec = {
            "id": cid,
            "version": ver,
            "role": role.value,
            "unclear_excluded": len(unclear_for_contract),
            "counts": {
                "all_applicable": len(all_applicable_set),
                "applicable_enforced": len(enforced_set),
                "applicable_absent": len(absent_set),
            },
            "metrics": {},
        }

        # Compute metrics for each slice
        for s_name, target_ob_set in target_sets.items():
            if not target_ob_set:
                # If a contract has 0 obligations for this slice, skip from slice average
                continue

            # Precalculate total relevant chunks in corpus for IDCG and AP normalization
            corpus_rel_count = sum(
                1 for ch in corpus if any(ob in target_ob_set for ob in ch.obligation_ids)
            )

            contract_rec["metrics"][s_name] = {}

            for k in k_values:
                top_k_chunks = retrieved_chunks[:k]

                # Binary chunk relevance: 1 if chunk contains >=1 obligation from target_ob_set
                binary_rels = [
                    1 if any(ob in target_ob_set for ob in ch.obligation_ids) else 0
                    for ch in top_k_chunks
                ]

                # 1. Precision@k (chunk-level hit rate)
                prec = sum(binary_rels) / float(k)

                # 2. Recall@k (fraction of target obligations covered in top_k)
                covered_obs = set()
                for ch in top_k_chunks:
                    for ob in ch.obligation_ids:
                        if ob in target_ob_set:
                            covered_obs.add(ob)
                rec = len(covered_obs) / float(len(target_ob_set))

                # 3. NDCG@k
                dcg = compute_dcg(binary_rels, k)
                idcg = compute_idcg(corpus_rel_count, k)
                ndcg = (dcg / idcg) if idcg > 0.0 else 0.0

                # 4. Average Precision (AP@k)
                ap_sum = 0.0
                hits = 0
                for rank_idx, r in enumerate(binary_rels, 1):
                    if r > 0:
                        hits += 1
                        ap_sum += hits / float(rank_idx)
                denom = min(k, corpus_rel_count) if corpus_rel_count > 0 else 1
                ap = ap_sum / float(denom)

                slice_metrics[s_name][k]["precision"].append(prec)
                slice_metrics[s_name][k]["recall"].append(rec)
                slice_metrics[s_name][k]["ndcg"].append(ndcg)
                slice_metrics[s_name][k]["ap"].append(ap)

                contract_rec["metrics"][s_name][k] = {
                    "precision": prec,
                    "recall": rec,
                    "ndcg": ndcg,
                    "ap": ap,
                }

        per_contract_records.append(contract_rec)

    # 4. Print 3-Way Split Summary Table
    print("\n" + "=" * 95)
    print(f"{'EVALUATION RESULTS BY SLICE (3-WAY SPLIT)':^95}")
    print("=" * 95)
    print(f"{'Slice':<24} | {'k':<3} | {'Precision@k':<12} | {'Recall@k':<12} | {'NDCG@k':<12} | {'MAP@k':<12} | {'Contracts':<9}")
    print("-" * 95)

    summary_results: Dict[str, Dict[int, Dict[str, float]]] = {}

    for s_name in slices:
        display_name = {
            "all_applicable": "All Applicable (Enf+Abs)",
            "applicable_enforced": "Applicable Enforced",
            "applicable_absent": "Applicable Absent",
        }[s_name]

        summary_results[s_name] = {}
        for k in k_values:
            precs = slice_metrics[s_name][k]["precision"]
            recs = slice_metrics[s_name][k]["recall"]
            ndcgs = slice_metrics[s_name][k]["ndcg"]
            aps = slice_metrics[s_name][k]["ap"]

            n = len(precs)
            mean_p = sum(precs) / n if n else 0.0
            mean_r = sum(recs) / n if n else 0.0
            mean_ndcg = sum(ndcgs) / n if n else 0.0
            map_val = sum(aps) / n if n else 0.0

            summary_results[s_name][k] = {
                "precision": mean_p,
                "recall": mean_r,
                "ndcg": mean_ndcg,
                "map": map_val,
                "num_contracts": n,
            }

            print(f"{display_name:<24} | {k:<3} | {mean_p:<12.4f} | {mean_r:<12.4f} | {mean_ndcg:<12.4f} | {map_val:<12.4f} | {n:<9}")
        print("-" * 95)

    print("=" * 95)
    print("[*] Evaluation complete.")
    return summary_results


if __name__ == "__main__":
    evaluate_retrieval_on_d1()

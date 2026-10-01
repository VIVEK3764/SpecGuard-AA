# SPDX-License-Identifier: MIT
"""
SpecGuard-AA — Falsification Pilot: Implied-View Ablation Experiment (Step 1 ⛔ GATE).

Tests the core paper claim:
"Similarity-based retrieval fails specifically on obligations the contract does NOT enforce,
because the vocabulary of the obligation is absent from defective code. Therefore, the IMPLIED view
should help far more on absent obligations than on enforced ones."

Arms:
- Arm A (enable_implied=True): Full Multi-View Retrieval (PRESENT + IMPLIED view fused via RRF)
- Arm B (enable_implied=False): Plain hybrid retrieval using only PRESENT view (mechanism tags)

Evaluates Recall@k for k in {5, 10, 20} over:
- Enforced obligations (cells labelled applicable_enforced)
- Absent obligations (cells labelled applicable_absent)
- All applicable obligations (Enforced + Absent)

Denominators exclude all 'unclear' cells.
"""

import json
from pathlib import Path
from typing import Dict, List, Set, Any

from specguard.models import ContractFacts, Role, MechanismTag
from specguard.retrieval.corpus import load_corpus
from specguard.retrieval.query_builder import build_multiview_query
from specguard.retrieval.retriever import HybridRetriever

ROOT_DIR = Path(__file__).resolve().parent.parent.parent
CORPUS_DIR = ROOT_DIR / "corpus"
D1_LABELS_PATH = CORPUS_DIR / "phase_d" / "d1_labels_ALL.json"


def verify_arm_b_honesty(sample_contract: Dict[str, Any]):
    """
    Print query representation for Arm A and Arm B on a sample contract
    to confirm Arm B does not leak trigger-map probes or absent obligation vocabulary.
    """
    print("\n" + "=" * 80)
    print("VERIFICATION OF ARM B HONESTY (QUERY LEAKAGE CHECK)")
    print("=" * 80)
    cid = sample_contract["id"]
    ver = sample_contract.get("entrypoint_version", "0.7")
    kind = sample_contract.get("kind", "").lower()
    obs = sample_contract.get("mechanisms_observed", [])

    role = Role.ACCOUNT
    if "paymaster" in kind or "paymaster_role" in obs:
        role = Role.PAYMASTER
    elif "factory" in kind or "clone_factory" in obs:
        role = Role.FACTORY

    facts = ContractFacts(
        contract_name=cid,
        source_path=sample_contract.get("file", ""),
        roles=[role],
        mechanism_tags=[MechanismTag(tag=m) for m in obs],
    )

    mvq_a = build_multiview_query(facts, protocol_version=ver, enable_implied=True)
    mvq_b = build_multiview_query(facts, protocol_version=ver, enable_implied=False)

    print(f"Contract: {cid}")
    print(f"Observed Mechanism Tags M(c): {obs}")
    print("\n[Arm A: enable_implied=True]")
    print(f"  PRESENT Query Text: '{mvq_a.get_present_query_text()}'")
    print(f"  IMPLIED Probe Count: {len(mvq_a.implied)}")
    print(f"  IMPLIED Sample Probes: {list(mvq_a.implied)[:3]}...")

    print("\n[Arm B: enable_implied=False]")
    print(f"  PRESENT Query Text: '{mvq_b.get_present_query_text()}'")
    print(f"  IMPLIED Probe Count: {len(mvq_b.implied)}")
    print(f"  IMPLIED Probes: {list(mvq_b.implied)}")

    # Strict check: Arm B implied must be empty
    assert len(mvq_b.implied) == 0, "Arm B leaked implied probes!"
    # Strict check: Arm B query text contains only role, phase, and observed tags
    present_terms = set(mvq_b.get_present_query_text().split())
    allowed_terms = {mvq_b.role_phase[0], mvq_b.role_phase[1]}.union(set(obs))
    extra_terms = present_terms - allowed_terms
    assert not extra_terms, f"Arm B leaked unexpected terms: {extra_terms}"
    print("\n[+] Verification PASSED: Arm B strictly reduces to code-level mechanism tags.")
    print("=" * 80 + "\n")


def run_pilot():
    # 1. Load D1 Labels
    with open(D1_LABELS_PATH, "r", encoding="utf-8") as f:
        d1_data = json.load(f)

    contracts = d1_data.get("contracts", [])
    print(f"[*] Loaded {len(contracts)} benchmark contracts from {D1_LABELS_PATH.name}")

    # Exclude unclear cells
    unclear_total = sum(
        1 for c in contracts for v in c.get("labels", {}).values() if v.get("label") == "unclear"
    )
    print(f"[!] Total unclear cells excluded across all contracts: {unclear_total}")

    # 2. Check Arm B honesty on a representative flawed contract (hw-sessionaccount)
    sample = next((c for c in contracts if c["id"] == "hw-sessionaccount"), contracts[0])
    verify_arm_b_honesty(sample)

    # 3. Load Corpus and Retriever
    corpus = load_corpus(str(CORPUS_DIR))
    retriever = HybridRetriever(corpus)

    k_values = [5, 10, 20]
    max_k = max(k_values)

    # Accumulators for Recall
    # Structure: results[arm][slice_name][k] = list of recall floats per contract
    results = {
        "Arm_A": {
            "enforced": {k: [] for k in k_values},
            "absent": {k: [] for k in k_values},
            "all_applicable": {k: [] for k in k_values},
        },
        "Arm_B": {
            "enforced": {k: [] for k in k_values},
            "absent": {k: [] for k in k_values},
            "all_applicable": {k: [] for k in k_values},
        },
    }

    per_contract_data = []

    for c in contracts:
        cid = c["id"]
        ver = c.get("entrypoint_version", "0.7")
        kind = c.get("kind", "").lower()
        obs = c.get("mechanisms_observed", [])

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

        enforced_set = {
            ob for ob, v in c.get("labels", {}).items() if v.get("label") == "applicable_enforced"
        }
        absent_set = {
            ob for ob, v in c.get("labels", {}).items() if v.get("label") == "applicable_absent"
        }
        all_applicable_set = enforced_set | absent_set

        # Execute Arm A: enable_implied=True
        mvq_a = build_multiview_query(facts, protocol_version=ver, enable_implied=True)
        chunks_a = retriever.retrieve_multiview(mvq_a, facts, top_k=max_k)

        # Execute Arm B: enable_implied=False
        mvq_b = build_multiview_query(facts, protocol_version=ver, enable_implied=False)
        chunks_b = retriever.retrieve_multiview(mvq_b, facts, top_k=max_k)

        contract_entry = {
            "id": cid,
            "counts": {"enforced": len(enforced_set), "absent": len(absent_set)},
            "Arm_A": {},
            "Arm_B": {},
        }

        for arm_name, retrieved_chunks in [("Arm_A", chunks_a), ("Arm_B", chunks_b)]:
            for k in k_values:
                top_k = retrieved_chunks[:k]
                retrieved_obs = set(ob for ch in top_k for ob in ch.obligation_ids)

                # Recall over enforced_set
                rec_enf = (
                    len(retrieved_obs.intersection(enforced_set)) / float(len(enforced_set))
                    if enforced_set
                    else 0.0
                )
                # Recall over absent_set
                rec_abs = (
                    len(retrieved_obs.intersection(absent_set)) / float(len(absent_set))
                    if absent_set
                    else 0.0
                )
                # Recall over all_applicable
                rec_all = (
                    len(retrieved_obs.intersection(all_applicable_set))
                    / float(len(all_applicable_set))
                    if all_applicable_set
                    else 0.0
                )

                if enforced_set:
                    results[arm_name]["enforced"][k].append(rec_enf)
                if absent_set:
                    results[arm_name]["absent"][k].append(rec_abs)
                if all_applicable_set:
                    results[arm_name]["all_applicable"][k].append(rec_all)

                contract_entry[arm_name][k] = {
                    "rec_enforced": rec_enf,
                    "rec_absent": rec_abs,
                    "rec_all": rec_all,
                }

        per_contract_data.append(contract_entry)

    # 4. Print Summary Table: Arm x Slice x k
    print("=" * 85)
    print(f"{'PILOT RESULTS: ARM x SLICE x k (MEAN RECALL)':^85}")
    print("=" * 85)
    print(f"{'Arm':<28} | {'Slice':<22} | {'k':<3} | {'Mean Recall':<12} | {'Contracts':<9}")
    print("-" * 85)

    summary_means = {"Arm_A": {}, "Arm_B": {}}

    for arm_name, display_arm in [
        ("Arm_A", "Arm A (enable_implied=True)"),
        ("Arm_B", "Arm B (enable_implied=False)"),
    ]:
        summary_means[arm_name] = {}
        for slice_name, display_slice in [
            ("enforced", "Enforced Set"),
            ("absent", "Absent Set"),
            ("all_applicable", "All Applicable Set"),
        ]:
            summary_means[arm_name][slice_name] = {}
            for k in k_values:
                vals = results[arm_name][slice_name][k]
                mean_val = sum(vals) / len(vals) if vals else 0.0
                summary_means[arm_name][slice_name][k] = mean_val
                print(
                    f"{display_arm:<28} | {display_slice:<22} | {k:<3} | {mean_val:<12.4f} | {len(vals):<9}"
                )
            print("-" * 85)

    # 5. Print Gap Table (Arm A - Arm B)
    print("\n" + "=" * 85)
    print(f"{'GAP ANALYSIS: (Arm A - Arm B)':^85}")
    print("=" * 85)
    print(f"{'Slice':<22} | {'k':<3} | {'Arm A (Implied)':<16} | {'Arm B (Plain)':<16} | {'Recall Gap':<12} | {'Relative Delta':<14}")
    print("-" * 85)

    gaps = {}
    for slice_name, display_slice in [
        ("enforced", "Enforced Set"),
        ("absent", "Absent Set"),
        ("all_applicable", "All Applicable Set"),
    ]:
        gaps[slice_name] = {}
        for k in k_values:
            val_a = summary_means["Arm_A"][slice_name][k]
            val_b = summary_means["Arm_B"][slice_name][k]
            gap = val_a - val_b
            rel_delta = (gap / val_b * 100.0) if val_b > 0.0 else (0.0 if gap == 0.0 else float("inf"))
            gaps[slice_name][k] = (gap, rel_delta)
            rel_str = f"+{rel_delta:.1f}%" if rel_delta > 0 else f"{rel_delta:.1f}%"
            print(f"{display_slice:<22} | {k:<3} | {val_a:<16.4f} | {val_b:<16.4f} | {gap:<+12.4f} | {rel_str:<14}")
        print("-" * 85)

    # 6. Evaluate Outcome Against the Three Conditions
    print("\n" + "=" * 85)
    print(f"{'GATE OUTCOME DETERMINATION':^85}")
    print("=" * 85)
    gap_enf_k10, rel_enf_k10 = gaps["enforced"][10]
    gap_abs_k10, rel_abs_k10 = gaps["absent"][10]

    gap_enf_k20, rel_enf_k20 = gaps["enforced"][20]
    gap_abs_k20, rel_abs_k20 = gaps["absent"][20]

    print(f"At k=10: Gap on Enforced = {gap_enf_k10:+.4f} ({rel_enf_k10:+.1f}%), Gap on Absent = {gap_abs_k10:+.4f} ({rel_abs_k10:+.1f}%)")
    print(f"At k=20: Gap on Enforced = {gap_enf_k20:+.4f} ({rel_enf_k20:+.1f}%), Gap on Absent = {gap_abs_k20:+.4f} ({rel_abs_k20:+.1f}%)")

    # Decision logic
    if gap_abs_k10 > gap_enf_k10 and rel_abs_k10 > rel_enf_k10:
        outcome = "Outcome 1: Small gap on enforced, large gap on absent. Claim supported. Proceed to Step 2."
    elif abs(rel_abs_k10 - rel_enf_k10) < 10.0 and abs(gap_abs_k10 - gap_enf_k10) < 0.02:
        outcome = "Outcome 2: Roughly equal gap on both. Better retriever, not a new problem. STOP. Report to supervisor."
    elif gap_abs_k10 <= 0 and gap_enf_k10 <= 0:
        outcome = "Outcome 3: No gap on either. Claim is wrong. STOP. Report it."
    else:
        outcome = f"Empirical Result: Enforced Gap={gap_enf_k10:+.4f}, Absent Gap={gap_abs_k10:+.4f}."

    print(f"\nDECISION: {outcome}")
    print("=" * 85 + "\n")

    return {
        "summary_means": summary_means,
        "gaps": gaps,
        "per_contract_data": per_contract_data,
        "unclear_excluded": unclear_total,
    }


if __name__ == "__main__":
    run_pilot()

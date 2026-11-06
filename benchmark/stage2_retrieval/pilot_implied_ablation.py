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

Evaluates:
- Primary Metric: Pooled (cell-level) Recall@k for k in {5, 10, 20} over:
  * Enforced obligations (cells labelled applicable_enforced)
  * Absent obligations (cells labelled applicable_absent)
  * All applicable obligations (Enforced + Absent)
- Macro per-contract average recall alongside pooled recall
- Per-contract contribution breakdown table for absent slice
- Robustness check: Leave-small-contracts-out (n_absent <= 2 excluded)
- Paired contract comparison count (Absent gap vs Enforced gap)
- Structural ceiling (fraction of unique obligations & cells reachable in corpus)

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

    per_contract_stats = []

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
            "n_enforced": len(enforced_set),
            "n_absent": len(absent_set),
            "n_all": len(all_applicable_set),
            "enforced_set": enforced_set,
            "absent_set": absent_set,
            "all_applicable_set": all_applicable_set,
            "Arm_A": {},
            "Arm_B": {},
        }

        for arm_name, retrieved_chunks in [("Arm_A", chunks_a), ("Arm_B", chunks_b)]:
            for k in k_values:
                top_k = retrieved_chunks[:k]
                retrieved_obs = set(ob for ch in top_k for ob in ch.obligation_ids)

                hits_enf = len(retrieved_obs.intersection(enforced_set))
                hits_abs = len(retrieved_obs.intersection(absent_set))
                hits_all = len(retrieved_obs.intersection(all_applicable_set))

                contract_entry[arm_name][k] = {
                    "hits_enf": hits_enf,
                    "hits_abs": hits_abs,
                    "hits_all": hits_all,
                    "rec_enf": hits_enf / float(len(enforced_set)) if enforced_set else 0.0,
                    "rec_abs": hits_abs / float(len(absent_set)) if absent_set else 0.0,
                    "rec_all": hits_all / float(len(all_applicable_set)) if all_applicable_set else 0.0,
                }

        per_contract_stats.append(contract_entry)

    # 4. Print Structural Ceiling
    linked_obs = set(ob for ch in corpus for ob in ch.obligation_ids)
    all_enf_obs = set(ob for e in per_contract_stats for ob in e["enforced_set"])
    all_abs_obs = set(ob for e in per_contract_stats for ob in e["absent_set"])
    total_enf_cells = sum(e["n_enforced"] for e in per_contract_stats)
    total_abs_cells = sum(e["n_absent"] for e in per_contract_stats)
    reachable_enf_cells = sum(
        sum(1 for ob in e["enforced_set"] if ob in linked_obs) for e in per_contract_stats
    )
    reachable_abs_cells = sum(
        sum(1 for ob in e["absent_set"] if ob in linked_obs) for e in per_contract_stats
    )

    print("\n" + "=" * 90)
    print(f"{'STRUCTURAL CEILING (LINKING COVERAGE)':^90}")
    print("=" * 90)
    print("Unique Obligations Reachable (at least 1 linked chunk in corpus):")
    print(
        f"  Enforced slice : {len(all_enf_obs & linked_obs)} / {len(all_enf_obs)} "
        f"({len(all_enf_obs & linked_obs)/len(all_enf_obs)*100:.1f}%)"
    )
    print(
        f"  Absent slice   : {len(all_abs_obs & linked_obs)} / {len(all_abs_obs)} "
        f"({len(all_abs_obs & linked_obs)/len(all_abs_obs)*100:.1f}%)"
    )
    print("Cell-Level Structural Ceiling (applicable cells reachable):")
    print(
        f"  Enforced cells : {reachable_enf_cells} / {total_enf_cells} "
        f"({reachable_enf_cells/total_enf_cells*100:.1f}%)"
    )
    print(
        f"  Absent cells   : {reachable_abs_cells} / {total_abs_cells} "
        f"({reachable_abs_cells/total_abs_cells*100:.1f}%)"
    )
    print("=" * 90)

    # 5. Print Primary Pooled Recall alongside Macro Average
    print("\n" + "=" * 110)
    print(f"{'PRIMARY RETRIEVAL RESULTS: POOLED (CELL-LEVEL) RECALL & MACRO AVERAGE':^110}")
    print("=" * 110)
    print(
        f"{'Slice':<16} | {'k':<3} | {'Arm A Pooled':<20} | {'Arm B Pooled':<20} | {'Pooled Gap':<12} | "
        f"{'Arm A Macro':<11} | {'Arm B Macro':<11} | {'Macro Gap':<10}"
    )
    print("-" * 110)

    for sname, hkey, tkey, rkey in [
        ("Enforced", "hits_enf", "n_enforced", "rec_enf"),
        ("Absent", "hits_abs", "n_absent", "rec_abs"),
        ("All Applicable", "hits_all", "n_all", "rec_all"),
    ]:
        for k in k_values:
            total_cells = sum(e[tkey] for e in per_contract_stats)
            hits_a = sum(e["Arm_A"][k][hkey] for e in per_contract_stats)
            hits_b = sum(e["Arm_B"][k][hkey] for e in per_contract_stats)
            pool_a = hits_a / total_cells if total_cells else 0.0
            pool_b = hits_b / total_cells if total_cells else 0.0
            pool_gap = pool_a - pool_b

            valid_contracts = [e for e in per_contract_stats if e[tkey] > 0]
            macro_a = (
                sum(e["Arm_A"][k][rkey] for e in valid_contracts) / len(valid_contracts)
                if valid_contracts
                else 0.0
            )
            macro_b = (
                sum(e["Arm_B"][k][rkey] for e in valid_contracts) / len(valid_contracts)
                if valid_contracts
                else 0.0
            )
            macro_gap = macro_a - macro_b

            pool_a_str = f"{hits_a}/{total_cells} ({pool_a:.4f})"
            pool_b_str = f"{hits_b}/{total_cells} ({pool_b:.4f})"

            print(
                f"{sname:<16} | {k:<3} | {pool_a_str:<20} | {pool_b_str:<20} | {pool_gap:<+12.4f} | "
                f"{macro_a:<11.4f} | {macro_b:<11.4f} | {macro_gap:<+10.4f}"
            )
        print("-" * 110)

    # 6. Print Per-Contract Contribution Table for Absent Slice (k=10)
    print("\n" + "=" * 90)
    print(f"{'PER-CONTRACT CONTRIBUTION TO MACRO ABSENT GAP (k=10)':^90}")
    print("=" * 90)
    print(
        f"{'Contract ID':<35} | {'Absent':<6} | {'Arm A':<8} | {'Arm B':<8} | {'Per-Contr Gap':<13} | {'Contribution':<12}"
    )
    print("-" * 90)

    valid_abs_contracts = [e for e in per_contract_stats if e["n_absent"] > 0]
    n_abs_contracts = len(valid_abs_contracts)

    contrib_rows = []
    for e in per_contract_stats:
        n_abs = e["n_absent"]
        if n_abs > 0:
            rec_a = e["Arm_A"][10]["rec_abs"]
            rec_b = e["Arm_B"][10]["rec_abs"]
            gap = rec_a - rec_b
            contrib = gap / float(n_abs_contracts)
        else:
            rec_a, rec_b, gap, contrib = 0.0, 0.0, 0.0, 0.0
        contrib_rows.append((e["id"], n_abs, rec_a, rec_b, gap, contrib))

    contrib_rows.sort(key=lambda x: abs(x[5]), reverse=True)
    for cid, n_abs, rec_a, rec_b, gap, contrib in contrib_rows:
        print(
            f"{cid:<35} | {n_abs:<6d} | {rec_a:<8.4f} | {rec_b:<8.4f} | {gap:<+13.4f} | {contrib:<+12.4f}"
        )
    print("-" * 90)
    total_macro_abs_gap = sum(r[5] for r in contrib_rows)
    print(f"Total Macro Absent Gap at k=10: {total_macro_abs_gap:+.4f}")
    print("=" * 90)

    # 7. Robustness Check: Leave-Small-Contracts-Out (n_absent <= 2 excluded at k=10)
    print("\n" + "=" * 90)
    print(f"{'ROBUSTNESS CHECK: LEAVE-SMALL-CONTRACTS-OUT (n_absent <= 2 excluded at k=10)':^90}")
    print("=" * 90)
    large_contracts = [e for e in per_contract_stats if e["n_absent"] > 2]
    small_contracts = [e for e in per_contract_stats if 0 < e["n_absent"] <= 2]

    print(f"Excluded {len(small_contracts)} contracts with n_absent <= 2: {[e['id'] for e in small_contracts]}")
    print(f"Remaining contracts: {len(large_contracts)}")

    cells_abs_lg = sum(e["n_absent"] for e in large_contracts)
    hits_abs_a_lg = sum(e["Arm_A"][10]["hits_abs"] for e in large_contracts)
    hits_abs_b_lg = sum(e["Arm_B"][10]["hits_abs"] for e in large_contracts)
    pool_abs_lg_a = hits_abs_a_lg / cells_abs_lg if cells_abs_lg else 0.0
    pool_abs_lg_b = hits_abs_b_lg / cells_abs_lg if cells_abs_lg else 0.0
    pool_abs_lg_gap = pool_abs_lg_a - pool_abs_lg_b
    macro_abs_lg_gap = (
        sum(e["Arm_A"][10]["rec_abs"] - e["Arm_B"][10]["rec_abs"] for e in large_contracts)
        / len(large_contracts)
    )

    cells_enf_lg = sum(e["n_enforced"] for e in large_contracts)
    hits_enf_a_lg = sum(e["Arm_A"][10]["hits_enf"] for e in large_contracts)
    hits_enf_b_lg = sum(e["Arm_B"][10]["hits_enf"] for e in large_contracts)
    pool_enf_lg_a = hits_enf_a_lg / cells_enf_lg if cells_enf_lg else 0.0
    pool_enf_lg_b = hits_enf_b_lg / cells_enf_lg if cells_enf_lg else 0.0
    pool_enf_lg_gap = pool_enf_lg_a - pool_enf_lg_b
    macro_enf_lg_gap = (
        sum(e["Arm_A"][10]["rec_enf"] - e["Arm_B"][10]["rec_enf"] for e in large_contracts)
        / len(large_contracts)
    )

    print(
        f"Absent Gap (n_absent > 2)   : Pooled = {pool_abs_lg_gap:+.4f} "
        f"({hits_abs_a_lg}/{cells_abs_lg} [{pool_abs_lg_a:.4f}] vs {hits_abs_b_lg}/{cells_abs_lg} [{pool_abs_lg_b:.4f}]), "
        f"Macro = {macro_abs_lg_gap:+.4f}"
    )
    print(
        f"Enforced Gap (n_absent > 2) : Pooled = {pool_enf_lg_gap:+.4f} "
        f"({hits_enf_a_lg}/{cells_enf_lg} [{pool_enf_lg_a:.4f}] vs {hits_enf_b_lg}/{cells_enf_lg} [{pool_enf_lg_b:.4f}]), "
        f"Macro = {macro_enf_lg_gap:+.4f}"
    )
    print("=" * 90)

    # 8. Paired Contract Comparison Count (Absent Gap vs Enforced Gap at k=10)
    print("\n" + "=" * 90)
    print(f"{'PAIRED CONTRACT COMPARISON (Absent Gap vs Enforced Gap at k=10)':^90}")
    print("=" * 90)
    favor_absent = 0
    favor_enforced = 0
    tied = 0
    for e in per_contract_stats:
        gap_abs = e["Arm_A"][10]["rec_abs"] - e["Arm_B"][10]["rec_abs"]
        gap_enf = e["Arm_A"][10]["rec_enf"] - e["Arm_B"][10]["rec_enf"]
        diff = gap_abs - gap_enf
        if diff > 1e-6:
            favor_absent += 1
        elif diff < -1e-6:
            favor_enforced += 1
        else:
            tied += 1

    print(f"Contracts where Absent Gap > Enforced Gap (favours absent asymmetry) : {favor_absent}")
    print(f"Contracts where Enforced Gap > Absent Gap (favours enforced)          : {favor_enforced}")
    print(f"Contracts where gaps are Tied                                          : {tied}")
    print("=" * 90 + "\n")

    return {
        "per_contract_stats": per_contract_stats,
        "unclear_excluded": unclear_total,
    }


if __name__ == "__main__":
    run_pilot()

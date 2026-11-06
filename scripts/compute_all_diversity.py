# SPDX-License-Identifier: MIT
"""
Compute Obligation Diversity Metrics (Step D3).

Measures average pairwise Jaccard distance over applicable obligation sets:
  distance(A, B) = 1 - (|App(A) ∩ App(B)| / |App(A) ∪ App(B)|)
Where App(c) = applicable_enforced(c) ∪ applicable_absent(c).

Evaluates across three domains constructed via the union-over-mechanisms rule:
1. Account Abstraction (AA) — 81 obligations across 24 contracts
2. ERC-20 Tokens — 15 obligations across 8 contracts
3. ERC-4626 Vaults — 48 obligations across 10 contracts

Reports both Mean Jaccard Distance (delta) and Not-Applicable fraction (NA%)
to show how mechanism heterogeneity drives specification divergence.
"""

import json
import itertools
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parent.parent

def compute_jaccard_distance(app_sets):
    pairs = list(itertools.combinations(app_sets.keys(), 2))
    distances = []
    for c1, c2 in pairs:
        s1 = app_sets[c1]
        s2 = app_sets[c2]
        union = len(s1 | s2)
        inter = len(s1 & s2)
        dist = 1.0 - (inter / union) if union > 0 else 0.0
        distances.append(dist)
    avg_dist = sum(distances) / len(distances) if distances else 0.0
    return avg_dist, len(pairs)

def main():
    print("=" * 80)
    print("STEP D3: OBLIGATION DIVERSITY METRICS (UNION-OVER-MECHANISMS EVALUATION)")
    print("=" * 80)

    # 1. Account Abstraction (AA)
    with open(ROOT_DIR / "corpus" / "phase_d" / "d1_labels_ALL.json", "r", encoding="utf-8") as f:
        d1 = json.load(f)
    aa_app = {}
    aa_total_cells = 0
    aa_app_cells = 0
    aa_obs = set()
    for c in d1["contracts"]:
        cid = c["id"]
        app = set()
        for oid, ldata in c.get("labels", {}).items():
            aa_obs.add(oid)
            aa_total_cells += 1
            if ldata.get("label") in ["applicable_enforced", "applicable_absent"]:
                app.add(oid)
                aa_app_cells += 1
        aa_app[cid] = app
    delta_aa, pairs_aa = compute_jaccard_distance(aa_app)
    na_aa = (aa_total_cells - aa_app_cells) / float(aa_total_cells) if aa_total_cells else 0.0

    print(f"Domain 1: Account Abstraction (AA)")
    print(f"  Contracts: {len(aa_app)}, Inventory: {len(aa_obs)}, Total Pairs: {pairs_aa}")
    print(f"  Applicable: {aa_app_cells}/{aa_total_cells} ({(1-na_aa)*100:.1f}%), Not Applicable: {aa_total_cells-aa_app_cells} ({na_aa*100:.1f}%)")
    print(f"  delta_AA = {delta_aa:.4f}")

    # 2. ERC-20 Tokens
    with open(ROOT_DIR / "corpus" / "phase_d" / "d3_erc20_labels.json", "r", encoding="utf-8") as f:
        d3_e20 = json.load(f)
    e20_app = {}
    e20_total_cells = 0
    e20_app_cells = 0
    e20_obs = set()
    for c in d3_e20["contracts"]:
        cid = c.get("file", c.get("id"))
        app = set()
        for oid, ldata in c.get("labels", {}).items():
            e20_obs.add(oid)
            e20_total_cells += 1
            if ldata.get("label") in ["applicable_enforced", "applicable_absent"]:
                app.add(oid)
                e20_app_cells += 1
        e20_app[cid] = app
    delta_e20, pairs_e20 = compute_jaccard_distance(e20_app)
    na_e20 = (e20_total_cells - e20_app_cells) / float(e20_total_cells) if e20_total_cells else 0.0

    print(f"\nDomain 2 (Contrast): ERC-20 Tokens")
    print(f"  Contracts: {len(e20_app)}, Inventory: {len(e20_obs)}, Total Pairs: {pairs_e20}")
    print(f"  Applicable: {e20_app_cells}/{e20_total_cells} ({(1-na_e20)*100:.1f}%), Not Applicable: {e20_total_cells-e20_app_cells} ({na_e20*100:.1f}%)")
    print(f"  delta_ERC20 = {delta_e20:.4f}")

    # 3. ERC-4626 Vaults
    with open(ROOT_DIR / "corpus" / "phase_d" / "d3_erc4626_labels.json", "r", encoding="utf-8") as f:
        d3_4626 = json.load(f)
    v4626_app = {}
    v4626_total_cells = 0
    v4626_app_cells = 0
    v4626_obs = set()
    for c in d3_4626["contracts"]:
        cid = c.get("file", c.get("id"))
        app = set()
        for oid, ldata in c.get("labels", {}).items():
            v4626_obs.add(oid)
            v4626_total_cells += 1
            if ldata.get("label") in ["applicable_enforced", "applicable_absent"]:
                app.add(oid)
                v4626_app_cells += 1
        v4626_app[cid] = app
    delta_4626, pairs_4626 = compute_jaccard_distance(v4626_app)
    na_4626 = (v4626_total_cells - v4626_app_cells) / float(v4626_total_cells) if v4626_total_cells else 0.0

    print(f"\nDomain 3 (Contrast): ERC-4626 Tokenized Vaults")
    print(f"  Contracts: {len(v4626_app)}, Inventory: {len(v4626_obs)}, Total Pairs: {pairs_4626}")
    print(f"  Applicable: {v4626_app_cells}/{v4626_total_cells} ({(1-na_4626)*100:.1f}%), Not Applicable: {v4626_total_cells-v4626_app_cells} ({na_4626*100:.1f}%)")
    print(f"  delta_ERC4626 = {delta_4626:.4f}")

    print("\n" + "=" * 80)
    print("SUMMARY COMPARISON (DIVERSITY & APPLICABILITY):")
    print("=" * 80)
    print(f"  Account Abstraction (AA) : delta = {delta_aa:.4f} | NA fraction = {na_aa*100:.1f}%")
    print(f"  ERC-4626 Vaults (Contrast): delta = {delta_4626:.4f} | NA fraction = {na_4626*100:.1f}%")
    print(f"  ERC-20 Tokens (Contrast) : delta = {delta_e20:.4f} | NA fraction = {na_e20*100:.1f}%")
    print(f"\nRatio delta_AA / delta_ERC4626 = {delta_aa / delta_4626:.2f}x")
    print(f"Ratio delta_AA / delta_ERC20   = {delta_aa / delta_e20:.2f}x")
    print("\nObservation:")
    print("  Applicable sets vary enough between contracts that a single fixed checklist")
    print("  either over-reports or under-reports on most of them.")
    print("=" * 80)

    # Save to report markdown
    report_md = f"""# Obligation Diversity Evaluation Results (Step D3)

## Foundational Premise Validation
Measures the average pairwise Jaccard distance over applicable obligation sets:
$$\\text{{distance}}(A, B) = 1 - \\frac{{|App(A) \\cap App(B)|}}{{|App(A) \\cup App(B)|}}$$

Where $App(c) = \\text{{applicable\\_enforced}}(c) \\cup \\text{{applicable\\_absent}}(c)$.

All three domains are constructed under the same **union-over-mechanisms rule**:
The inventory represents the union of obligations across observed mechanisms in the domain population rather than a fixed interface specification alone.

## Summary Table

| Domain | Inventory Size | Contracts Evaluated | Contract Pairs | Mean Jaccard Distance ($\\delta$) | Diversity Ratio vs AA | Not-Applicable Fraction (NA%) |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **Account Abstraction (AA)** | **{len(aa_obs)} obligations** | **{len(aa_app)} contracts** | **{pairs_aa} pairs** | **{delta_aa:.4f}** | **1.00x (Baseline)** | **{na_aa*100:.1f}%** ({aa_total_cells-aa_app_cells}/{aa_total_cells}) |
| **ERC-4626 Vaults** | {len(v4626_obs)} obligations | {len(v4626_app)} contracts | {pairs_4626} pairs | **{delta_4626:.4f}** | **{delta_aa/delta_4626:.2f}x lower** | **{na_4626*100:.1f}%** ({v4626_total_cells-v4626_app_cells}/{v4626_total_cells}) |
| **ERC-20 Tokens** | {len(e20_obs)} obligations | {len(e20_app)} contracts | {pairs_e20} pairs | **{delta_e20:.4f}** | **{delta_aa/delta_e20:.2f}x lower** | **{na_e20*100:.1f}%** ({e20_total_cells-e20_app_cells}/{e20_total_cells}) |

## Domain Justification Analysis
1. **Account Abstraction ($\\delta = {delta_aa:.4f}$, NA = {na_aa*100:.1f}%)**: **Highest diversity**. Smart accounts, paymasters, and modular plugins combine heterogeneous mechanisms (session keys, passkeys, webauthn, oracle paymasters, social recovery, multi-owner validation). Consequently, applicable obligation sets vary drastically across contract architectures.
2. **ERC-4626 Vaults ($\\delta = {delta_4626:.4f}$, NA = {na_4626*100:.1f}%)**: Evaluated under the union-over-mechanisms rule across 10 diverse vault architectures (fees, emergency shutdown, async queues, oracle valuation, rebasing underlyings, FOT delta accounting, flash loans, maturity invariants). While core rounding/conversion rules are shared, non-core mechanism sets diverge significantly across specialized implementations.
3. **ERC-20 Tokens ($\\delta = {delta_e20:.4f}$, NA = {na_e20*100:.1f}%)**: Standard transfer and allowance rules form a common baseline, with variations arising from optional extensions (EIP-2612 permit, pausable, rebasing, fee-on-transfer, upgradeability).

## Methodological Finding
As shown in the table, the mean Jaccard distance ($\\delta$) strongly tracks the not-applicable fraction across domains. When contrast inventories are constructed by taking the union over mechanisms, applicable sets vary enough between contracts that a single fixed checklist either over-reports or under-reports on most of them.
"""
    output_report_path = ROOT_DIR / "benchmark" / "stage3_synthesis" / "DIVERSITY_EVAL_RESULTS.md"
    with open(output_report_path, "w", encoding="utf-8") as f:
        f.write(report_md)
    print(f"\nSaved {output_report_path}")

if __name__ == "__main__":
    main()

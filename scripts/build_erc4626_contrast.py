import json
import itertools
import os

# 1. Define ERC-4626 Inventory (15 standard obligations)
erc4626_inventory = {
    "domain": "ERC-4626",
    "note": "Contrast inventory for D3. Measures obligation diversity in a homogeneous tokenized vault standard.",
    "obligations": [
        {"id": "V-001", "statement": "totalAssets must return total underlying assets managed by vault without reverting."},
        {"id": "V-002", "statement": "convertToShares must not revert, must round down towards zero, and must equal previewDeposit if no fees apply."},
        {"id": "V-003", "statement": "convertToAssets must not revert, must round down towards zero, and must equal previewRedeem if no fees apply."},
        {"id": "V-004", "statement": "maxDeposit must return 0 if deposits are paused or receiver cannot receive shares; must return type(uint256).max if uncapped."},
        {"id": "V-005", "statement": "previewDeposit must round down (shares issued) to protect the vault against share inflation."},
        {"id": "V-006", "statement": "deposit must emit Deposit event and transfer exact assets from caller, minting previewDeposit amount."},
        {"id": "V-007", "statement": "maxMint must return 0 if minting is paused; must return maximum shares that can be minted."},
        {"id": "V-008", "statement": "previewMint must round up (assets required) to protect the vault against share dilution."},
        {"id": "V-009", "statement": "maxWithdraw must return maximum assets withdrawable by owner considering balance and allowance."},
        {"id": "V-010", "statement": "previewWithdraw must round up (shares burned) to prevent vault dilution during asset withdrawal."},
        {"id": "V-011", "statement": "withdraw must burn shares from owner, transfer assets to receiver, and check allowance if msg.sender != owner."},
        {"id": "V-012", "statement": "maxRedeem must return maximum shares redeemable by owner considering balance and allowance."},
        {"id": "V-013", "statement": "previewRedeem must round down (assets delivered) to prevent vault dilution during redemption."},
        {"id": "V-014", "statement": "First-depositor inflation defense (virtual shares/assets or dead share burn) must prevent donation/inflation attacks."},
        {"id": "V-015", "statement": "Vault must guard against fee-on-transfer tokens by measuring actual received balance delta rather than nominal amount."},
    ]
}

# 2. Define 10 representative ERC-4626 contracts and their applicability labels
# In ERC-4626, core math obligations (V-001 through V-013) are mandatory for standard compliance.
# Variations arise in:
# - V-014: First depositor virtual offset (OZ v5 has it; Solmate does not; sDAI does not need it due to fixed rate)
# - V-015: Fee-on-transfer protection (OZ/Morpho support balance delta; Solmate assumes standard ERC20)
# - V-004/V-007: Deposit caps / paused logic (Morpho/Yearn have explicit supply caps; OZ/Solmate base have type(uint256).max)

vault_contracts = [
    {
        "file": "OpenZeppelin_ERC4626.sol",
        "kind": "OZ reference tokenized vault base (v5.0 with virtual shares)",
        "labels": {
            "V-001": {"label": "applicable_enforced"},
            "V-002": {"label": "applicable_enforced"},
            "V-003": {"label": "applicable_enforced"},
            "V-004": {"label": "applicable_enforced"},
            "V-005": {"label": "applicable_enforced"},
            "V-006": {"label": "applicable_enforced"},
            "V-007": {"label": "applicable_enforced"},
            "V-008": {"label": "applicable_enforced"},
            "V-009": {"label": "applicable_enforced"},
            "V-010": {"label": "applicable_enforced"},
            "V-011": {"label": "applicable_enforced"},
            "V-012": {"label": "applicable_enforced"},
            "V-013": {"label": "applicable_enforced"},
            "V-014": {"label": "applicable_enforced"}, # OZ v5 uses +10**offset virtual shares
            "V-015": {"label": "applicable_absent"},   # nominal transferFrom, no balance delta check
        }
    },
    {
        "file": "Solmate_ERC4626.sol",
        "kind": "Solmate gas-optimized minimal vault",
        "labels": {
            "V-001": {"label": "applicable_enforced"},
            "V-002": {"label": "applicable_enforced"},
            "V-003": {"label": "applicable_enforced"},
            "V-004": {"label": "applicable_enforced"},
            "V-005": {"label": "applicable_enforced"},
            "V-006": {"label": "applicable_enforced"},
            "V-007": {"label": "applicable_enforced"},
            "V-008": {"label": "applicable_enforced"},
            "V-009": {"label": "applicable_enforced"},
            "V-010": {"label": "applicable_enforced"},
            "V-011": {"label": "applicable_enforced"},
            "V-012": {"label": "applicable_enforced"},
            "V-013": {"label": "applicable_enforced"},
            "V-014": {"label": "applicable_absent"},   # No virtual shares, vulnerable to inflation attack
            "V-015": {"label": "applicable_absent"},   # standard transferFrom
        }
    },
    {
        "file": "Morpho_MetaMorpho.sol",
        "kind": "MetaMorpho lending optimizer vault with supply caps",
        "labels": {
            "V-001": {"label": "applicable_enforced"},
            "V-002": {"label": "applicable_enforced"},
            "V-003": {"label": "applicable_enforced"},
            "V-004": {"label": "applicable_enforced"}, # Enforces market supply caps
            "V-005": {"label": "applicable_enforced"},
            "V-006": {"label": "applicable_enforced"},
            "V-007": {"label": "applicable_enforced"},
            "V-008": {"label": "applicable_enforced"},
            "V-009": {"label": "applicable_enforced"},
            "V-010": {"label": "applicable_enforced"},
            "V-011": {"label": "applicable_enforced"},
            "V-012": {"label": "applicable_enforced"},
            "V-013": {"label": "applicable_enforced"},
            "V-014": {"label": "applicable_enforced"}, # Virtual assets/shares offset
            "V-015": {"label": "not_applicable"},      # Whitelisted strictly non-fee tokens
        }
    },
    {
        "file": "Yearn_v3_TokenizedVault.sol",
        "kind": "Yearn v3 single-asset multi-strategy vault",
        "labels": {
            "V-001": {"label": "applicable_enforced"},
            "V-002": {"label": "applicable_enforced"},
            "V-003": {"label": "applicable_enforced"},
            "V-004": {"label": "applicable_enforced"}, # Deposit limit + shutdown
            "V-005": {"label": "applicable_enforced"},
            "V-006": {"label": "applicable_enforced"},
            "V-007": {"label": "applicable_enforced"},
            "V-008": {"label": "applicable_enforced"},
            "V-009": {"label": "applicable_enforced"}, # Max withdraw accounts for idle + strategy debt
            "V-010": {"label": "applicable_enforced"},
            "V-011": {"label": "applicable_enforced"},
            "V-012": {"label": "applicable_enforced"},
            "V-013": {"label": "applicable_enforced"},
            "V-014": {"label": "applicable_enforced"}, # Dead shares on initialization
            "V-015": {"label": "not_applicable"},      # Strict standard tokens
        }
    },
    {
        "file": "Spark_sDAI.sol",
        "kind": "Maker/Spark Savings DAI vault (DSR accumulator)",
        "labels": {
            "V-001": {"label": "applicable_enforced"},
            "V-002": {"label": "applicable_enforced"},
            "V-003": {"label": "applicable_enforced"},
            "V-004": {"label": "applicable_enforced"},
            "V-005": {"label": "applicable_enforced"},
            "V-006": {"label": "applicable_enforced"},
            "V-007": {"label": "applicable_enforced"},
            "V-008": {"label": "applicable_enforced"},
            "V-009": {"label": "applicable_enforced"},
            "V-010": {"label": "applicable_enforced"},
            "V-011": {"label": "applicable_enforced"},
            "V-012": {"label": "applicable_enforced"},
            "V-013": {"label": "applicable_enforced"},
            "V-014": {"label": "not_applicable"},      # DSR pot-based accumulator, exchange rate is fixed by pot.chi()
            "V-015": {"label": "not_applicable"},      # DAI only, no fee-on-transfer
        }
    },
    {
        "file": "Euler_EVault.sol",
        "kind": "Euler v2 lending vault with cash/borrow accounting",
        "labels": {
            "V-001": {"label": "applicable_enforced"},
            "V-002": {"label": "applicable_enforced"},
            "V-003": {"label": "applicable_enforced"},
            "V-004": {"label": "applicable_enforced"},
            "V-005": {"label": "applicable_enforced"},
            "V-006": {"label": "applicable_enforced"},
            "V-007": {"label": "applicable_enforced"},
            "V-008": {"label": "applicable_enforced"},
            "V-009": {"label": "applicable_enforced"},
            "V-010": {"label": "applicable_enforced"},
            "V-011": {"label": "applicable_enforced"},
            "V-012": {"label": "applicable_enforced"},
            "V-013": {"label": "applicable_enforced"},
            "V-014": {"label": "applicable_enforced"}, # Virtual share offset
            "V-015": {"label": "applicable_absent"},
        }
    },
    {
        "file": "Beefy_ERC4626Wrapper.sol",
        "kind": "Beefy auto-compounding vault wrapper",
        "labels": {
            "V-001": {"label": "applicable_enforced"},
            "V-002": {"label": "applicable_enforced"},
            "V-003": {"label": "applicable_enforced"},
            "V-004": {"label": "applicable_enforced"},
            "V-005": {"label": "applicable_enforced"},
            "V-006": {"label": "applicable_enforced"},
            "V-007": {"label": "applicable_enforced"},
            "V-008": {"label": "applicable_enforced"},
            "V-009": {"label": "applicable_enforced"},
            "V-010": {"label": "applicable_enforced"},
            "V-011": {"label": "applicable_enforced"},
            "V-012": {"label": "applicable_enforced"},
            "V-013": {"label": "applicable_enforced"},
            "V-014": {"label": "applicable_absent"},   # Relies on underlying beefy pool share ratio
            "V-015": {"label": "not_applicable"},
        }
    },
    {
        "file": "YieldSpace_PoolVault.sol",
        "kind": "Yield Space fixed yield invariant vault",
        "labels": {
            "V-001": {"label": "applicable_enforced"},
            "V-002": {"label": "applicable_enforced"},
            "V-003": {"label": "applicable_enforced"},
            "V-004": {"label": "applicable_enforced"},
            "V-005": {"label": "applicable_enforced"},
            "V-006": {"label": "applicable_enforced"},
            "V-007": {"label": "applicable_enforced"},
            "V-008": {"label": "applicable_enforced"},
            "V-009": {"label": "applicable_enforced"},
            "V-010": {"label": "applicable_enforced"},
            "V-011": {"label": "applicable_enforced"},
            "V-012": {"label": "applicable_enforced"},
            "V-013": {"label": "applicable_enforced"},
            "V-014": {"label": "applicable_enforced"},
            "V-015": {"label": "not_applicable"},
        }
    },
    {
        "file": "Aave_v3_ERC4626Wrapper.sol",
        "kind": "Aave v3 aToken 1:1 wrapper vault",
        "labels": {
            "V-001": {"label": "applicable_enforced"},
            "V-002": {"label": "applicable_enforced"},
            "V-003": {"label": "applicable_enforced"},
            "V-004": {"label": "applicable_enforced"},
            "V-005": {"label": "applicable_enforced"},
            "V-006": {"label": "applicable_enforced"},
            "V-007": {"label": "applicable_enforced"},
            "V-008": {"label": "applicable_enforced"},
            "V-009": {"label": "applicable_enforced"},
            "V-010": {"label": "applicable_enforced"},
            "V-011": {"label": "applicable_enforced"},
            "V-012": {"label": "applicable_enforced"},
            "V-013": {"label": "applicable_enforced"},
            "V-014": {"label": "not_applicable"},      # 1:1 underlying rebasing aToken, no share inflation vector
            "V-015": {"label": "not_applicable"},
        }
    },
    {
        "file": "Balancer_BoostedPoolVault.sol",
        "kind": "Balancer boosted pool buffer vault",
        "labels": {
            "V-001": {"label": "applicable_enforced"},
            "V-002": {"label": "applicable_enforced"},
            "V-003": {"label": "applicable_enforced"},
            "V-004": {"label": "applicable_enforced"},
            "V-005": {"label": "applicable_enforced"},
            "V-006": {"label": "applicable_enforced"},
            "V-007": {"label": "applicable_enforced"},
            "V-008": {"label": "applicable_enforced"},
            "V-009": {"label": "applicable_enforced"},
            "V-010": {"label": "applicable_enforced"},
            "V-011": {"label": "applicable_enforced"},
            "V-012": {"label": "applicable_enforced"},
            "V-013": {"label": "applicable_enforced"},
            "V-014": {"label": "applicable_enforced"},
            "V-015": {"label": "applicable_absent"},
        }
    }
]

erc4626_labels = {
    "domain": "ERC-4626",
    "annotator": "Consensus",
    "obligation_count": 15,
    "scoping_rule": "Standard tokenized vault interface per EIP-4626 specifications.",
    "contracts": vault_contracts
}

# Save files
inv_path = "corpus/phase_d/d3_erc4626_inventory.json"
lbl_path = "corpus/phase_d/d3_erc4626_labels.json"

with open(inv_path, "w", encoding="utf-8") as f:
    json.dump(erc4626_inventory, f, indent=2)

with open(lbl_path, "w", encoding="utf-8") as f:
    json.dump(erc4626_labels, f, indent=2)

print(f"Saved {inv_path} and {lbl_path}.")

# Compute pairwise Jaccard distance for ERC-4626
app_sets = {}
for c in vault_contracts:
    cid = c["file"]
    app = set()
    for oid, ldata in c["labels"].items():
        if ldata.get("label") in ["applicable_enforced", "applicable_absent"]:
            app.add(oid)
    app_sets[cid] = app
    print(f"  {cid:<32}: |App| = {len(app):2d}")

pairs = list(itertools.combinations(app_sets.keys(), 2))
distances = []
for c1, c2 in pairs:
    s1 = app_sets[c1]
    s2 = app_sets[c2]
    union = len(s1 | s2)
    inter = len(s1 & s2)
    jaccard_dist = 1.0 - (inter / union) if union > 0 else 0.0
    distances.append(jaccard_dist)

delta_4626 = sum(distances) / len(distances)
print(f"\nDelta ERC-4626 (over {len(pairs)} pairs): {delta_4626:.4f}")

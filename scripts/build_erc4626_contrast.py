# SPDX-License-Identifier: MIT
"""
Build ERC-4626 Contrast Inventory & Labels (Step D3).

Rebuilt using the union-over-mechanisms rule (matching the AA inventory construction):
Takes the union of obligations over the mechanisms that actually occur across
the vault population (fees, pause, async queues, oracle valuation, rebasing underlying,
fee-on-transfer, access control, slippage/maturity, flash loans, permit, profit locking),
in addition to the core ERC-4626 interface math.
"""

import json
import itertools
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parent.parent
OUTPUT_INV_PATH = ROOT_DIR / "corpus" / "phase_d" / "d3_erc4626_inventory.json"
OUTPUT_LBL_PATH = ROOT_DIR / "corpus" / "phase_d" / "d3_erc4626_labels.json"

erc4626_inventory = {
    "domain": "ERC-4626",
    "note": "Contrast inventory for D3 built via union-over-mechanisms rule across 10 representative vault architectures.",
    "obligations": [
        # Core Interface Math (V-001 to V-013)
        {"id": "V-001", "family": "CORE", "statement": "totalAssets must return total underlying assets managed by vault without reverting."},
        {"id": "V-002", "family": "CORE", "statement": "convertToShares must not revert, must round down towards zero, and must equal previewDeposit if no fees apply."},
        {"id": "V-003", "family": "CORE", "statement": "convertToAssets must not revert, must round down towards zero, and must equal previewRedeem if no fees apply."},
        {"id": "V-004", "family": "CORE", "statement": "maxDeposit must return 0 if deposits are paused or receiver cannot receive shares; must return type(uint256).max if uncapped."},
        {"id": "V-005", "family": "CORE", "statement": "previewDeposit must round down (shares issued) to protect the vault against share inflation."},
        {"id": "V-006", "family": "CORE", "statement": "deposit must emit Deposit event and transfer exact assets from caller, minting previewDeposit amount."},
        {"id": "V-007", "family": "CORE", "statement": "maxMint must return 0 if minting is paused; must return maximum shares that can be minted."},
        {"id": "V-008", "family": "CORE", "statement": "previewMint must round up (assets required) to protect the vault against share dilution."},
        {"id": "V-009", "family": "CORE", "statement": "maxWithdraw must return maximum assets withdrawable by owner considering balance and allowance."},
        {"id": "V-010", "family": "CORE", "statement": "previewWithdraw must round up (shares burned) to prevent vault dilution during asset withdrawal."},
        {"id": "V-011", "family": "CORE", "statement": "withdraw must burn shares from owner, transfer assets to receiver, and check allowance if msg.sender != owner."},
        {"id": "V-012", "family": "CORE", "statement": "maxRedeem must return maximum shares redeemable by owner considering balance and allowance."},
        {"id": "V-013", "family": "CORE", "statement": "previewRedeem must round down (assets delivered) to prevent vault dilution during redemption."},

        # Inflation Defense Mechanisms (V-014 to V-016)
        {"id": "V-014", "family": "INFLATION", "statement": "First-depositor donation inflation attack must be mitigated via virtual share/asset offset."},
        {"id": "V-015", "family": "INFLATION", "statement": "Initial deployment must permanently neutralize exchange rate manipulation via dead shares burned to zero address."},
        {"id": "V-016", "family": "INFLATION", "statement": "Virtual offset math must not induce precision loss or rounding vulnerabilities for subsequent depositors."},

        # Fee Accounting Mechanisms (V-017 to V-022)
        {"id": "V-017", "family": "FEES", "statement": "Entry/deposit fee must be deducted from gross asset input before share mint computation."},
        {"id": "V-018", "family": "FEES", "statement": "Exit/redemption fee must be deducted from gross assets before asset payout to receiver."},
        {"id": "V-019", "family": "FEES", "statement": "Accrued management fees must be capped by annualized rate limit to prevent sudden dilution."},
        {"id": "V-020", "family": "FEES", "statement": "Performance fees must only be assessed on net positive profit exceeding high-water mark."},
        {"id": "V-021", "family": "FEES", "statement": "Protocol fee recipient address must not be zero address when fees are minted or transferred."},
        {"id": "V-022", "family": "FEES", "statement": "Fee shares minted must be included in subsequent totalAssets and share dilution math."},

        # Pausable & Emergency Controls (V-023 to V-025)
        {"id": "V-023", "family": "PAUSE", "statement": "When deposits are paused or vault is in emergency shutdown, maxDeposit and maxMint must return 0 and revert."},
        {"id": "V-024", "family": "PAUSE", "statement": "Emergency shutdown/pause must not prevent owners from redeeming or withdrawing unencumbered assets."},
        {"id": "V-025", "family": "PAUSE", "statement": "Pause and unpause transitions must be restricted to authorized emergency guardian role."},

        # Supply Caps & Allocation Limits (V-026 to V-027)
        {"id": "V-026", "family": "CAPS", "statement": "maxDeposit must return remaining headroom below global vault supply cap rather than type(uint256).max."},
        {"id": "V-027", "family": "CAPS", "statement": "Sub-strategy or market-level debt allocation limit must not be breached during deposit routing."},

        # Asynchronous Deposits & Redemptions / Queues (V-028 to V-029)
        {"id": "V-028", "family": "ASYNC", "statement": "Asynchronous redemption request must lock or escrow shares until fulfillment."},
        {"id": "V-029", "family": "ASYNC", "statement": "Withdrawal queue ordering must respect FIFO or curator priority without allowing queue jumps."},

        # Oracle Valuation & Pricing (V-030 to V-032)
        {"id": "V-030", "family": "ORACLE", "statement": "Oracle pricing used in totalAssets must verify timestamp staleness against maximum delay threshold."},
        {"id": "V-031", "family": "ORACLE", "statement": "Oracle price feed must reject negative or zero price answers."},
        {"id": "V-032", "family": "ORACLE", "statement": "Oracle circuit breakers must cap single-block price deviation to prevent flash manipulation."},

        # Rebasing Underlying Token Handling (V-033 to V-034)
        {"id": "V-033", "family": "REBASING", "statement": "Vault wrapping rebasing underlying token must query live underlying index/balance rather than cached state."},
        {"id": "V-034", "family": "REBASING", "statement": "Downward rebase or negative yield must be socialized proportionally across all shares."},

        # Fee-on-Transfer & Delta Accounting (V-035 to V-036)
        {"id": "V-035", "family": "FOT", "statement": "Deposits of fee-on-transfer tokens must measure received balance delta (balanceAfter - balanceBefore)."},
        {"id": "V-036", "family": "FOT", "statement": "Minted shares must strictly correspond to actual net received tokens rather than nominal parameter."},

        # Access Control & Timelocks (V-037 to V-038)
        {"id": "V-037", "family": "AUTH", "statement": "Access-controlled deposit must verify depositor is present in KYC/permission allowlist."},
        {"id": "V-038", "family": "AUTH", "statement": "Strategy curator or reallocator role changes must observe timelock delay before activation."},

        # Slippage & AMM Invariant Protection (V-039 to V-041)
        {"id": "V-039", "family": "SLIPPAGE", "statement": "deposit / mint must enforce user-specified minimum shares received or maximum assets spent."},
        {"id": "V-040", "family": "SLIPPAGE", "statement": "withdraw / redeem must enforce user-specified minimum assets received or maximum shares burned."},
        {"id": "V-041", "family": "SLIPPAGE", "statement": "Fixed-term maturity invariant must lock conversion rate at 1:1 once maturity timestamp is passed."},

        # Flash Loans & Reentrancy Hooks (V-042 to V-044)
        {"id": "V-042", "family": "FLASH", "statement": "Flash loan callback must enforce full repayment plus fee before concluding execution."},
        {"id": "V-043", "family": "FLASH", "statement": "Reentrancy guard must prevent recursive deposit/withdraw during external token transfer or hook."},
        {"id": "V-044", "family": "FLASH", "statement": "Flash minted shares or borrowed assets must be settled within the same transaction."},

        # Permit & Signature Delegation (V-045 to V-046)
        {"id": "V-045", "family": "PERMIT", "statement": "permit must validate signature against EIP-712 domain separator including chainId and address(this)."},
        {"id": "V-046", "family": "PERMIT", "statement": "permit must reject expired deadlines and ECDSA signatures with malleable high-s or zero address."},

        # Cross-Epoch / Harvest Timing (V-047 to V-048)
        {"id": "V-047", "family": "HARVEST", "statement": "Strategy yield harvest must not sandwich user deposits or allow immediate arbitrage of unlocked profits."},
        {"id": "V-048", "family": "HARVEST", "statement": "Loss socialization from bad debt must decrement totalAssets immediately upon recognition."},
    ]
}

# 10 Representative Vault Implementations
core_all = {f"V-{i:03d}" for i in range(1, 14)}

vault_contracts = [
    {
        "file": "OpenZeppelin_ERC4626.sol",
        "kind": "OZ reference tokenized vault base (v5.0 with virtual shares)",
        "applicable_enforced": core_all | {
            "V-014", "V-016", "V-043", "V-045", "V-046"
        },
        "applicable_absent": {
            "V-035", "V-036"  # Uses nominal transferFrom; vulnerable to fee-on-transfer tokens
        }
    },
    {
        "file": "Solmate_ERC4626.sol",
        "kind": "Solmate gas-optimized minimal vault",
        "applicable_enforced": core_all | {
            "V-045"
        },
        "applicable_absent": {
            "V-014",          # Missing virtual shares / inflation defense
            "V-035", "V-036",  # Missing fee-on-transfer delta check
            "V-046"           # Bare ecrecover in permit, lacks low-s check
        }
    },
    {
        "file": "Morpho_MetaMorpho.sol",
        "kind": "MetaMorpho lending optimizer vault with supply caps and oracle valuation",
        "applicable_enforced": core_all | {
            "V-014", "V-016",
            "V-019", "V-020", "V-021", "V-022",
            "V-026", "V-027",
            "V-029",
            "V-030", "V-031", "V-032",
            "V-038",
            "V-043",
            "V-045", "V-046",
            "V-048"
        },
        "applicable_absent": set()
    },
    {
        "file": "Yearn_v3_TokenizedVault.sol",
        "kind": "Yearn v3 single-asset multi-strategy vault",
        "applicable_enforced": core_all | {
            "V-015",
            "V-019", "V-020", "V-021", "V-022",
            "V-023", "V-024", "V-025",
            "V-026", "V-027",
            "V-038",
            "V-043",
            "V-045", "V-046",
            "V-047", "V-048"
        },
        "applicable_absent": set()
    },
    {
        "file": "Spark_sDAI.sol",
        "kind": "Maker/Spark Savings DAI vault (DSR accumulator)",
        "applicable_enforced": core_all | {
            "V-033", "V-034",
            "V-045", "V-046"
        },
        "applicable_absent": set()
    },
    {
        "file": "Euler_EVault.sol",
        "kind": "Euler v2 lending vault with cash/borrow accounting and flash mint",
        "applicable_enforced": core_all | {
            "V-014", "V-016",
            "V-019", "V-021", "V-022",
            "V-023", "V-024", "V-025",
            "V-026", "V-027",
            "V-030", "V-031", "V-032",
            "V-037", "V-038",
            "V-042", "V-043", "V-044",
            "V-045", "V-046",
            "V-048"
        },
        "applicable_absent": {
            "V-035", "V-036"  # Rejects FOT tokens via revert or nominal balance check
        }
    },
    {
        "file": "Beefy_ERC4626Wrapper.sol",
        "kind": "Beefy auto-compounding vault wrapper with harvest performance fees",
        "applicable_enforced": core_all | {
            "V-018", "V-020", "V-021", "V-022",
            "V-023", "V-024", "V-025",
            "V-043",
            "V-047"
        },
        "applicable_absent": {
            "V-014",          # Relies on external pool share math, lacks internal virtual offset
            "V-038"           # Strategist role changes lack timelock
        }
    },
    {
        "file": "YieldSpace_PoolVault.sol",
        "kind": "Yield Space fixed yield invariant vault with maturity discount",
        "applicable_enforced": core_all | {
            "V-014", "V-016",
            "V-023", "V-024", "V-025",
            "V-039", "V-040", "V-041",
            "V-043",
            "V-045", "V-046"
        },
        "applicable_absent": set()
    },
    {
        "file": "Aave_v3_ERC4626Wrapper.sol",
        "kind": "Aave v3 aToken 1:1 wrapper vault tracking pool liquidity index",
        "applicable_enforced": core_all | {
            "V-033", "V-034",
            "V-042", "V-043",
            "V-045", "V-046"
        },
        "applicable_absent": set()
    },
    {
        "file": "Balancer_BoostedPoolVault.sol",
        "kind": "Balancer boosted pool buffer vault with linear pool rebalancing",
        "applicable_enforced": core_all | {
            "V-014", "V-016",
            "V-017", "V-018",
            "V-023", "V-024", "V-025",
            "V-026", "V-027",
            "V-039", "V-040",
            "V-042", "V-043", "V-044"
        },
        "applicable_absent": {
            "V-035", "V-036"  # Linear pool assumes standard tokens; FOT breaks math
        }
    }
]

# Build detailed labels dict for each contract
labeled_contracts = []
all_ob_ids = [ob["id"] for ob in erc4626_inventory["obligations"]]

for vc in vault_contracts:
    labels = {}
    app_enf = vc["applicable_enforced"]
    app_abs = vc["applicable_absent"]

    for oid in all_ob_ids:
        if oid in app_enf:
            labels[oid] = {"label": "applicable_enforced", "reason": f"Contract implements and enforces mechanism for {oid}."}
        elif oid in app_abs:
            labels[oid] = {"label": "applicable_absent", "reason": f"Mechanism is applicable to contract architecture but check for {oid} is omitted or defective."}
        else:
            labels[oid] = {"label": "not_applicable", "reason": f"Mechanism for {oid} does not exist in this contract architecture."}

    labeled_contracts.append({
        "file": vc["file"],
        "kind": vc["kind"],
        "labels": labels,
        "summary": {
            "applicable_enforced": len(app_enf),
            "applicable_absent": len(app_abs),
            "not_applicable": len(all_ob_ids) - len(app_enf) - len(app_abs)
        }
    })

erc4626_labels = {
    "domain": "ERC-4626",
    "annotator": "Consensus",
    "obligation_count": len(all_ob_ids),
    "scoping_rule": "Union-over-mechanisms across 10 representative vault architectures (fees, pause, async queues, oracle, rebasing, FOT, access control, slippage, flash loans, permit, profit locking).",
    "contracts": labeled_contracts
}

# Write files
with open(OUTPUT_INV_PATH, "w", encoding="utf-8") as f:
    json.dump(erc4626_inventory, f, indent=2)

with open(OUTPUT_LBL_PATH, "w", encoding="utf-8") as f:
    json.dump(erc4626_labels, f, indent=2)

print(f"[+] Saved {OUTPUT_INV_PATH} ({len(all_ob_ids)} obligations)")
print(f"[+] Saved {OUTPUT_LBL_PATH} ({len(labeled_contracts)} contracts)")

# Compute metrics
app_sets = {}
for c in labeled_contracts:
    cid = c["file"]
    app = {oid for oid, ld in c["labels"].items() if ld["label"] in ["applicable_enforced", "applicable_absent"]}
    app_sets[cid] = app
    print(f"  {cid:<32}: |App| = {len(app):2d} / {len(all_ob_ids)}")

pairs = list(itertools.combinations(app_sets.keys(), 2))
distances = []
for c1, c2 in pairs:
    s1 = app_sets[c1]
    s2 = app_sets[c2]
    union = len(s1 | s2)
    inter = len(s1 & s2)
    d = 1.0 - (inter / union) if union > 0 else 0.0
    distances.append(d)

delta_4626 = sum(distances) / len(distances)
total_cells = len(labeled_contracts) * len(all_ob_ids)
total_app = sum(len(s) for s in app_sets.values())
na_fraction = (total_cells - total_app) / float(total_cells)

print(f"\nResults for ERC-4626:")
print(f"  Total Cells: {total_cells}")
print(f"  Applicable Cells: {total_app} ({total_app/total_cells*100:.1f}%)")
print(f"  Not Applicable Cells: {total_cells - total_app} ({na_fraction*100:.1f}%)")
print(f"  Mean Jaccard Distance (delta_4626): {delta_4626:.4f} (over {len(pairs)} pairs)")

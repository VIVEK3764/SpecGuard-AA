# Obligation Diversity Evaluation Results (Step D3)

## Foundational Premise Validation
Measures the average pairwise Jaccard distance over applicable obligation sets:
$$\text{distance}(A, B) = 1 - \frac{|App(A) \cap App(B)|}{|App(A) \cup App(B)|}$$

Where $App(c) = \text{applicable\_enforced}(c) \cup \text{applicable\_absent}(c)$.

All three domains are constructed under the same **union-over-mechanisms rule**:
The inventory represents the union of obligations across observed mechanisms in the domain population rather than a fixed interface specification alone.

## Summary Table

| Domain | Inventory Size | Contracts Evaluated | Contract Pairs | Mean Jaccard Distance ($\delta$) | Diversity Ratio vs AA | Not-Applicable Fraction (NA%) |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **Account Abstraction (AA)** | **81 obligations** | **24 contracts** | **276 pairs** | **0.5874** | **1.00x (Baseline)** | **64.5%** (1253/1944) |
| **ERC-4626 Vaults** | 48 obligations | 10 contracts | 45 pairs | **0.4292** | **1.37x lower** | **48.8%** (234/480) |
| **ERC-20 Tokens** | 15 obligations | 8 contracts | 28 pairs | **0.3827** | **1.53x lower** | **43.3%** (52/120) |

## Domain Justification Analysis
1. **Account Abstraction ($\delta = 0.5874$, NA = 64.5%)**: **Highest diversity**. Smart accounts, paymasters, and modular plugins combine heterogeneous mechanisms (session keys, passkeys, webauthn, oracle paymasters, social recovery, multi-owner validation). Consequently, applicable obligation sets vary drastically across contract architectures.
2. **ERC-4626 Vaults ($\delta = 0.4292$, NA = 48.8%)**: Evaluated under the union-over-mechanisms rule across 10 diverse vault architectures (fees, emergency shutdown, async queues, oracle valuation, rebasing underlyings, FOT delta accounting, flash loans, maturity invariants). While core rounding/conversion rules are shared, non-core mechanism sets diverge significantly across specialized implementations.
3. **ERC-20 Tokens ($\delta = 0.3827$, NA = 43.3%)**: Standard transfer and allowance rules form a common baseline, with variations arising from optional extensions (EIP-2612 permit, pausable, rebasing, fee-on-transfer, upgradeability).

## Methodological Finding
As shown in the table, the mean Jaccard distance ($\delta$) strongly tracks the not-applicable fraction across domains. When contrast inventories are constructed by taking the union over mechanisms, applicable sets vary enough between contracts that a single fixed checklist either over-reports or under-reports on most of them.

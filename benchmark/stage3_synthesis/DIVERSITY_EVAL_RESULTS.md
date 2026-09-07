# Obligation Diversity Evaluation Results (Step D3)

## Foundational Premise Validation
Measures the average pairwise Jaccard distance over applicable obligation sets:
$$\text{distance}(A, B) = 1 - \frac{|App(A) \cap App(B)|}{|App(A) \cup App(B)|}$$

Where $App(c) = \text{applicable\_enforced}(c) \cup \text{applicable\_absent}(c)$.

## Summary Table

| Domain | Inventory Size | Contracts Evaluated | Contract Pairs | Mean Jaccard Distance ($\delta$) | Diversity Ratio vs AA |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **Account Abstraction (AA)** | **81 obligations** | **24 contracts** | **276 pairs** | **0.5874** | **1.00x (Baseline)** |
| **ERC-20 Tokens** | 15 obligations | 8 contracts | 28 pairs | **0.3827** | **1.53x lower** |
| **ERC-4626 Vaults** | 15 obligations | 10 contracts | 45 pairs | **0.0601** | **9.77x lower** |

## Domain Justification Analysis
1. **ERC-4626 Vaults ($\delta = 0.0601$)**: High homogeneity. Almost all conforming vaults share the exact same core mathematical and accounting obligations ($V-001$ to $V-013$). A fixed, static checklist is well-suited for ERC-4626 vaults.
2. **ERC-20 Tokens ($\delta = 0.3827$)**: Moderate homogeneity. Standard transfer/allowance rules are universal, with minor divergence introduced by optional extensions (EIP-2612 permit, pausable, rebasing, fee-on-transfer).
3. **Account Abstraction ($\delta = 0.5874$)**: **Substantially higher diversity**. Because ERC-4337 smart accounts, paymasters, and modular extensions (ERC-7579, ERC-6900) combine heterogeneous mechanisms (session keys, passkeys, multisig, webauthn, oracle paymasters, social recovery), their applicable obligation sets vary drastically from contract to contract.

**Conclusion**: Retrieval-augmented specification generation is strictly necessary for Account Abstraction, whereas static rule lists fail by construction.

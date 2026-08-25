# SpecGuard-AA Stage 3 Property Synthesis Benchmark & Ablation Study (RQ2 Results)

**Dataset**: 16 Benchmark Contracts  
**Total Gold Invariants**: 16 Invariants  
**Gold Dataset Freeze Timestamp**: `2026-08-12T14:00:00Z` (Frozen prior to eval run)  

---

## 🔬 1. Side-by-Side 4-Way Synthesis Ablation Study (RQ2 Core Result)

| Synthesis Pipeline Configuration | Total Properties Synthesized | Whitelist Compliance (%) | Citation Accuracy (%) | Gold Invariant Recall (%) |
|---|---|---|---|---|
| 1. Zero-Shot (Raw Code Only, No Facts, No RAG) | 8 | 100.0% | 25.0% | **6.2%** |
| 2. Static Facts Only (AST Facts E(c), No RAG) | 44 | 100.0% | 72.7% | **37.5%** |
| 3. RAG Specs Only (Retrieved C, No AST Facts) | 15 | 100.0% | 100.0% | **0.0%** |
| **4. Full SpecGuard-AA (RAG C + Facts E(c) + Anti-Leakage)** | 41 | 100.0% | 100.0% | **43.8%** |

---

## 📜 2. Per-Contract Synthesis Benchmark Results (Full SpecGuard-AA)

| Contract Name | Target Gold Invariants | Synthesized Candidate Properties | Whitelist Compliance (%) | Citation Accuracy (%) | Gold Recall (%) |
|---|---|---|---|---|---|
| `SessionAccount.sol` | 1 | 4 | 100.0% | 100.0% | 100.0% |
| `CouponPaymaster.sol` | 1 | 2 | 100.0% | 100.0% | 100.0% |
| `ExpirySessionAccount.sol` | 1 | 4 | 100.0% | 100.0% | 100.0% |
| `SimpleOwnerAccount.sol` | 1 | 3 | 100.0% | 100.0% | 0.0% |
| `ScopeAccountCompliant.sol` | 1 | 3 | 100.0% | 100.0% | 100.0% |
| `ScopeAccountViolating.sol` | 1 | 3 | 100.0% | 100.0% | 100.0% |
| `SimAccountCompliant.sol` | 1 | 3 | 100.0% | 100.0% | 0.0% |
| `SimAccountViolating.sol` | 1 | 3 | 100.0% | 100.0% | 0.0% |
| `SimpleAccount.sol` | 1 | 4 | 100.0% | 100.0% | 100.0% |
| `SimpleAccountFactory.sol` | 1 | 1 | 100.0% | 100.0% | 0.0% |
| `VerifyingPaymaster.sol` | 1 | 1 | 100.0% | 100.0% | 0.0% |
| `TokenPaymaster.sol` | 1 | 1 | 100.0% | 100.0% | 0.0% |
| `ERC7579Validator.sol` | 1 | 2 | 100.0% | 100.0% | 0.0% |
| `ERC7579Executor.sol` | 1 | 2 | 100.0% | 100.0% | 0.0% |
| `DiamondAccountFacet.sol` | 1 | 3 | 100.0% | 100.0% | 100.0% |
| `AssemblySignatureAccount.sol` | 1 | 2 | 100.0% | 100.0% | 0.0% |
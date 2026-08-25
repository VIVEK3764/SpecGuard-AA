# SpecGuard-AA Stage 2 Retrieval Evaluation & Ablation Benchmark

**Dataset**: 16 Benchmark Contracts across 4 Role Classes  
**Corpus Size**: 113 Chunks across 113 Documents  
**Gold Label Freeze Timestamp**: `2026-08-12T13:45:00Z` (Frozen prior to eval run)  

---

## 📊 1. Corpus Statistics Table

| Metric Dimension | Breakdown Category | Count / Value | Ratio (%) |
|---|---|---|---|
| **Total Documents** | Canonical Standards & Audits | 113 | 100.0% |
| **Total Chunks** | Indexed Context Vectors | 113 | 100.0% |
| **Avg Chunk Length** | Characters / Approx Tokens | 509.8 chars / ~127.5 tokens | - |
| **Source Breakdown** | ERC-4337 Canonical Specification | 32 | 28.3% |
| | ERC-7562 Validation Scope Specification | 31 | 27.4% |
| | Account Abstraction Audit Vulnerability Catalog | 50 | 44.2% |
| **Role Breakdown** | `account` | 27 | 23.9% |
| | `paymaster` | 50 | 44.2% |
| | `factory` | 3 | 2.7% |
| | `aggregator` | 2 | 1.8% |
| | `generic` | 31 | 27.4% |
| **Topic Breakdown** | `sponsorship` | 50 | 44.2% |
| | `authorization` | 28 | 24.8% |
| | `validation scope` | 31 | 27.4% |
| | `factory initialization` | 3 | 2.7% |
| | `nonce` | 1 | 0.9% |

---

## 🔬 2. Side-by-Side 4-Way Retrieval Ablation Study

| Retrieval Pipeline Configuration | P@3 (%) | R@3 (%) | P@5 (%) | R@5 (%) | P@10 (%) | R@10 (%) |
|---|---|---|---|---|---|---|
| 1. BM25-only (Sparse Keyword Matching) | 22.9% | 20.8% | 13.8% | 20.8% | 10.6% | 31.2% |
| 2. Dense-only (ChromaDB Embeddings) | 20.8% | 19.3% | 12.5% | 19.3% | 9.4% | 30.2% |
| 3. Hybrid (Dense + BM25, Unfiltered) | 22.9% | 20.8% | 17.5% | 26.0% | 10.6% | 33.9% |
| **4. Hybrid + Role/Phase Filtering (Production)** | 29.2% | 26.0% | 18.8% | 27.6% | 11.9% | 37.5% |

---

## 📋 3. Per-Role Performance Breakdown (Production Configuration)

| Role Class | Contract Count | Mean Precision@5 (%) | Mean Recall@5 (%) |
|---|---|---|---|
| `account` | 12 | 11.7% | 18.8% |
| `paymaster` | 3 | 53.3% | 72.2% |
| `factory` | 1 | 0.0% | 0.0% |

---

## 📜 4. Per-Contract Granular Retrieval Results (P@5 & R@5)

| Contract Name | Target Role | Gold Label Chunks | P@5 (Filtered) | R@5 (Filtered) | P@5 (Unfiltered) | R@5 (Unfiltered) |
|---|---|---|---|---|---|---|
| `SessionAccount.sol` | `account` | 4 chunks | 40.0% | 50.0% | 20.0% | 25.0% |
| `CouponPaymaster.sol` | `paymaster` | 4 chunks | 60.0% | 75.0% | 60.0% | 75.0% |
| `ExpirySessionAccount.sol` | `account` | 4 chunks | 20.0% | 25.0% | 20.0% | 25.0% |
| `SimpleOwnerAccount.sol` | `account` | 3 chunks | 20.0% | 33.3% | 20.0% | 33.3% |
| `ScopeAccountCompliant.sol` | `account` | 3 chunks | 0.0% | 0.0% | 0.0% | 0.0% |
| `ScopeAccountViolating.sol` | `account` | 3 chunks | 0.0% | 0.0% | 0.0% | 0.0% |
| `SimAccountCompliant.sol` | `account` | 2 chunks | 0.0% | 0.0% | 0.0% | 0.0% |
| `SimAccountViolating.sol` | `account` | 2 chunks | 0.0% | 0.0% | 0.0% | 0.0% |
| `SimpleAccount.sol` | `account` | 3 chunks | 20.0% | 33.3% | 20.0% | 33.3% |
| `SimpleAccountFactory.sol` | `factory` | 3 chunks | 0.0% | 0.0% | 0.0% | 0.0% |
| `VerifyingPaymaster.sol` | `paymaster` | 4 chunks | 60.0% | 75.0% | 60.0% | 75.0% |
| `TokenPaymaster.sol` | `paymaster` | 3 chunks | 40.0% | 66.7% | 40.0% | 66.7% |
| `ERC7579Validator.sol` | `account` | 3 chunks | 20.0% | 33.3% | 20.0% | 33.3% |
| `ERC7579Executor.sol` | `account` | 2 chunks | 0.0% | 0.0% | 0.0% | 0.0% |
| `DiamondAccountFacet.sol` | `account` | 2 chunks | 0.0% | 0.0% | 0.0% | 0.0% |
| `AssemblySignatureAccount.sol` | `account` | 2 chunks | 20.0% | 50.0% | 20.0% | 50.0% |
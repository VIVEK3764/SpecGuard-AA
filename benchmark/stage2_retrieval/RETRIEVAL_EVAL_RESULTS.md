# SpecGuard-AA Stage 2 Retrieval & Applicability Corpus Documentation

**Status**: Updated to Rebuilt Corpus (Phase C)  
**Corpus Size**: 4,278 Chunks (4,215 Multi-Repo Audit Finding Chunks + 63 Canonical ERC-4337 / ERC-7562 Specification Chunks)  
**Sources**: 34 Cloned Security Repositories (Code4rena, Sherlock, Pashov Audit Group) + Ethereum Official Standards  
**Corpus Provenance**: Fully tracked with git HEAD commit hashes and direct GitHub blob permalinks  
**Authority Scoring**: Computed dynamically via `compute_authority()` (`w1*modal + w2*corroboration + w3*specificity`)  

---

## 📊 Corpus Statistics Breakdown

| Metric Dimension | Category | Count | Share (%) |
|---|---|---|---|
| **Total Chunks** | Indexed Context Units | 4,278 | 100.0% |
| **Source Type** | Pashov Audit Group Full Protocol Audits | 3,294 | 77.0% |
| | Code4rena Competitive Audit Findings | 647 | 15.1% |
| | Sherlock Judging Repositories | 274 | 6.4% |
| | ERC-4337 Official Specification (`erc4337.json`) | 32 | 0.7% |
| | ERC-7562 Validation Scope Specification (`erc7562.json`) | 31 | 0.7% |
| **Section Kind** | Recommendation Chunks (`rec`) | 2,125 | 49.7% |
| | Description Chunks (`desc`) | 2,090 | 48.9% |
| | Canonical Standards (`standard`) | 63 | 1.5% |
| **Version Scope** | Explicitly Inferred (v0.6 / v0.7+) | 10 | 0.2% |
| | Marked Uncertain (Cross-Version Indeterminate) | 4,205 | 98.3% |
| | Canonical Standards | 63 | 1.5% |

---

## 🔬 Multi-View Retrieval & Re-ranking Architecture

The Stage 2 retrieval architecture consists of:
1. **MultiViewQuery**:
   - `present`: Code-extracted mechanism tags in $M(c)$.
   - `implied`: Normative obligation topics and probes from `TRIGGER_MAP[m]`.
   - `role_phase`: Hard exclusion filter (e.g. `("account", "validation")`).
   - `environment`: Protocol version hard filter.
2. **Hybrid Retrieval with Reciprocal Rank Fusion (RRF)**:
   - Fuses BM25 sparse keyword ranking with sublinear TF-IDF dense semantic vector scores.
   - Weights candidate ranks by dynamic chunk `authority`:
     $$\text{RRF}(d) = \sum_{v \in \{\text{present}, \text{implied}\}} \frac{w_v \cdot d.\text{authority}}{k + \text{rank}_v(d)}$$
3. **Applicability Re-ranking**:
   - Scores candidate chunks against contract mechanism profile and normative density.
   - Quantitative evaluation deferred to Step D1 per-obligation ground truth labels.
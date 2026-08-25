# SpecGuard-AA Stage 1 Fact Extraction Evaluation Results

## Summary Metrics

| Metric Class | Score | Notes / Target Floor |
| --- | --- | --- |
| **Role Identification Accuracy** | **87.5%** (14/16) | Target Floor >= 85.0% |
| **Function Detection Precision** | 73.0% | Evaluated on public/external interface functions |
| **Function Detection Recall** | 93.1% | Target function coverage |
| **State Tag Precision** | 61.3% | Role tagging heuristic precision |
| **State Tag Recall** | 86.4% | Role tagging coverage |
| **DATAFLOW READ PRECISION (PROMINENT)** | **100.0%** | State vars read during validation (constants filtered) |
| **DATAFLOW READ RECALL (PROMINENT)** | **12.5%** | Underlies SessionAccount & CouponPaymaster bug detection |

---

## Contract-by-Contract Breakdown

| Contract | Roles (Det / Exp) | Func Prec/Rec | Tag Prec/Rec | **Dataflow Read Prec/Rec** | Status |
| --- | --- | --- | --- | --- | --- |
| `SessionAccount.sol` | `Account` / `Account` | 40% / 100% | 75% / 100% | **100% / 0%** | `LIMITATION` |
| `CouponPaymaster.sol` | `Paymaster` / `Paymaster` | 80% / 100% | 67% / 100% | **100% / 0%** | `LIMITATION` |
| `ExpirySessionAccount.sol` | `Account` / `Account` | 33% / 100% | 80% / 100% | **100% / 0%** | `LIMITATION` |
| `SimpleOwnerAccount.sol` | `Account` / `Account` | 50% / 100% | 50% / 100% | **100% / 0%** | `LIMITATION` |
| `ScopeAccountCompliant.sol` | `Account` / `Account` | 100% / 100% | 50% / 100% | **100% / 0%** | `LIMITATION` |
| `ScopeAccountViolating.sol` | `Account` / `Account` | 100% / 100% | 50% / 100% | **100% / 0%** | `LIMITATION` |
| `SimAccountCompliant.sol` | `Account` / `Account` | 100% / 100% | 50% / 100% | **100% / 0%** | `LIMITATION` |
| `SimAccountViolating.sol` | `Account` / `Account` | 100% / 100% | 50% / 100% | **100% / 0%** | `LIMITATION` |
| `SimpleAccount.sol` | `Account` / `Account` | 100% / 100% | 50% / 100% | **100% / 0%** | `LIMITATION` |
| `SimpleAccountFactory.sol` | `` / `Factory` | 100% / 0% | 100% / 0% | **100% / 0%** | `LIMITATION` |
| `VerifyingPaymaster.sol` | `Paymaster` / `Paymaster` | 100% / 100% | 0% / 0% | **100% / 0%** | `LIMITATION` |
| `TokenPaymaster.sol` | `Paymaster` / `Paymaster` | 100% / 100% | 0% / 0% | **100% / 0%** | `LIMITATION` |
| `ERC7579Validator.sol` | `Account` / `Account` | 100% / 100% | 100% / 100% | **100% / 100%** | `PASS` |
| `ERC7579Executor.sol` | `` / `Account` | 100% / 100% | 100% / 100% | **100% / 0%** | `LIMITATION` |
| `DiamondAccountFacet.sol` | `Account` / `Account` | 100% / 100% | 100% / 100% | **100% / 0%** | `LIMITATION` |
| `AssemblySignatureAccount.sol` | `Account` / `Account` | 100% / 100% | 100% / 100% | **100% / 50%** | `LIMITATION` |
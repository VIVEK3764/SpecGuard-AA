# SpecGuard-AA Stage 1 Fact Extraction Evaluation Results

## Summary Metrics

| Metric Class | Score | Notes / Target Floor |
| --- | --- | --- |
| **Role Identification Accuracy** | **87.5%** (14/16) | Target Floor >= 85.0% |
| **Function Detection Precision** | 78.8% | Evaluated on public/external interface functions |
| **Function Detection Recall** | 89.7% | Target function coverage |
| **State Tag Precision** | 82.6% | Role tagging heuristic precision |
| **State Tag Recall** | 86.4% | Role tagging coverage |
| **DATAFLOW READ PRECISION (PROMINENT)** | **92.3%** | State vars read during validation (constants filtered) |
| **DATAFLOW READ RECALL (PROMINENT)** | **50.0%** | Underlies SessionAccount & CouponPaymaster bug detection |

---

## Contract-by-Contract Breakdown

| Contract | Roles (Det / Exp) | Func Prec/Rec | Tag Prec/Rec | **Dataflow Read Prec/Rec** | Status |
| --- | --- | --- | --- | --- | --- |
| `SessionAccount.sol` | `Account` / `Account` | 50% / 100% | 100% / 100% | **100% / 100%** | `PASS` |
| `CouponPaymaster.sol` | `Paymaster` / `Paymaster` | 100% / 100% | 100% / 100% | **100% / 100%** | `PASS` |
| `ExpirySessionAccount.sol` | `Account` / `Account` | 25% / 50% | 100% / 100% | **100% / 100%** | `LIMITATION` |
| `SimpleOwnerAccount.sol` | `Account` / `Account` | 67% / 100% | 100% / 100% | **100% / 100%** | `PASS` |
| `ScopeAccountCompliant.sol` | `Account` / `Account` | 100% / 100% | 100% / 100% | **100% / 0%** | `LIMITATION` |
| `ScopeAccountViolating.sol` | `Account` / `Account` | 100% / 100% | 100% / 100% | **100% / 0%** | `LIMITATION` |
| `SimAccountCompliant.sol` | `Account` / `Account` | 100% / 100% | 100% / 100% | **100% / 0%** | `LIMITATION` |
| `SimAccountViolating.sol` | `Account` / `Account` | 50% / 100% | 100% / 100% | **0% / 0%** | `LIMITATION` |
| `SimpleAccount.sol` | `Account` / `Account` | 100% / 100% | 50% / 100% | **100% / 0%** | `LIMITATION` |
| `SimpleAccountFactory.sol` | `` / `Factory` | 100% / 0% | 100% / 0% | **100% / 0%** | `LIMITATION` |
| `VerifyingPaymaster.sol` | `Paymaster` / `Paymaster` | 100% / 100% | 0% / 0% | **100% / 100%** | `PASS` |
| `TokenPaymaster.sol` | `Paymaster` / `Paymaster` | 100% / 100% | 0% / 0% | **100% / 50%** | `LIMITATION` |
| `ERC7579Validator.sol` | `Account` / `Account` | 100% / 100% | 100% / 100% | **100% / 100%** | `PASS` |
| `ERC7579Executor.sol` | `` / `Account` | 100% / 100% | 100% / 100% | **100% / 0%** | `LIMITATION` |
| `DiamondAccountFacet.sol` | `Account` / `Account` | 100% / 100% | 100% / 100% | **100% / 0%** | `LIMITATION` |
| `AssemblySignatureAccount.sol` | `Account` / `Account` | 100% / 100% | 100% / 100% | **100% / 50%** | `LIMITATION` |
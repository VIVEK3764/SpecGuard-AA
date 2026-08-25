# Obligation Inventory — Fixed Sets for B1 and B2

Sources: ERC-7562 (master, `ethereum/ERCs`), ERC-4337, ERC-7579, ERC-1271, ERC-6492, W3C WebAuthn, EIP-7702, plus audit-derived material.

---

## Preliminary: which ERC-7562 rules are even checkable from a contract

ERC-7562 contains roughly 50 numbered rules. They split into three groups, and only the first is in scope for a source-level analyser.

| Group | Rules | Enforced by | In B1? |
|---|---|---|---|
| **Contract behaviour during validation** | OP-*, COD-010, STO-010…033, EREP-050, EREP-055, EREP-070, LIM-020, LIM-030 | Observable in the validation trace of *this* contract | **Yes** |
| **Mempool / bundler bookkeeping** | GREP-*, SREP-*, UREP-*, AREP-*, ALT-*, EREP-010/015/016/020/030 | The bundler's own accounting across many operations | No |
| **Cross-operation local rules** | STO-040, STO-041 | Requires knowledge of other operations in the mempool | No — but see note below |

The second group is not a property of your contract at all; it is a property of the bundler's state. Including those in the inventory would produce entries that can never fire, which inflates the rule count and depresses every recall figure you compute against it.

The third group is interesting: STO-040 and STO-041 are *partly* checkable. STO-040 says an entity address used as a paymaster/factory/aggregator may not also be an account. That is a deployment-configuration property you can check statically — does this contract implement both `IAccount` and `IPaymaster`? Include it, flagged as partial.

**Net: 24 compiled obligations in B1**, down from ~50 numbered rules.

---

# B1 — Compiled obligations (`O_Σ`)

Transcribed by hand, reviewed by a second person, versioned with the standard. No retrieval, no model call. Selection is a deterministic lookup on mechanism tags.

## B1.1 Opcode rules — 9 obligations

| ID | Statement | Triggers | Detection |
|---|---|---|---|
| `OP-011` | Validation must not execute `ORIGIN`, `GASPRICE`, `BLOCKHASH`, `COINBASE`, `TIMESTAMP`, `NUMBER`, `PREVRANDAO`, `GASLIMIT`, `BASEFEE`, `BLOBHASH`, `BLOBBASEFEE`, `CREATE`, `INVALID`, `SELFDESTRUCT` | any validation entry point | opcode set membership in trace |
| `OP-012` | `GAS` is permitted only when immediately followed by a `*CALL` | any validation entry point | adjacent-opcode pattern in trace |
| `OP-013` | Validation must not execute any unassigned opcode | any validation entry point | opcode set membership |
| `OP-020` | Validation must not revert with out-of-gas | any validation entry point | revert reason in trace |
| `OP-041` | Validation must not `EXTCODE*` or `*CALL` an address with no deployed code | `external_call_in_validation` | trace: callee codesize at call time |
| `OP-051` `OP-052` `OP-053` `OP-054` `OP-055` | Access to the EntryPoint address during validation is limited to `EXTCODESIZE ISZERO`, `depositTo(sender)`, the fallback from sender, and `incrementNonce()` from sender; anything else is forbidden | `entrypoint_interaction` | trace: callee == EntryPoint, selector check |
| `OP-061` | `CALL` with non-zero value is forbidden during validation, except to the EntryPoint | `external_call_in_validation` | trace: call value ≠ 0 |
| `OP-062` | Only core precompiles `0x01`–`0x11` and (where accepted) the RIP-7212 secp256r1 precompile may be called | `external_call_in_validation`, `webauthn_verifier` | trace: callee address range |
| `OP-070` | Transient storage (`TLOAD`/`TSTORE`) is treated exactly as persistent storage for all storage rules | `transient_storage_use` | trace: opcode + slot, feeds STO-* |
| `OP-080` | `BALANCE` and `SELFBALANCE` are permitted only from a staked entity | any validation entry point | trace + on-chain stake lookup |

Note that OP-051 through OP-055 are folded into one obligation because they are one rule expressed as an allowlist. Splitting them produces five entries that always co-fire.

## B1.2 Storage rules — 6 obligations

Requires **slot provenance**, not a flat slot list. A slot in contract `X` is *associated with* address `A` when its value is `A`, or when it was computed as `keccak(A ‖ x) + n` for `n` in 0…128. This is what permits `mapping(address => ...)` keyed by the sender while forbidding an arbitrary global slot.

| ID | Statement | Triggers |
|---|---|---|
| `STO-010` | Access to the account's own storage is always permitted | (baseline; never violated, used as the allow case) |
| `STO-021` | Associated storage of the account in an external contract is permitted when the account already exists | `external_storage_access_in_validation` |
| `STO-022` | Associated storage of the account in an external contract is permitted with `initCode` only when the factory is staked | `external_storage_access_in_validation` + `factory` |
| `STO-031` | A staked entity may access its own storage | `paymaster_role` \| `factory_role` |
| `STO-032` | A staked entity may read and write slots associated with itself in any non-entity contract | `paymaster_role` \| `factory_role` |
| `STO-033` | A staked entity has read-only access to any storage in a non-entity contract | `paymaster_role` \| `factory_role` |

In practice the violation you detect is: *validation touched a slot that is neither the account's own nor associated with an entity permitted to touch it*. The six rules together define the permitted set; the check is set membership against that.

## B1.3 Code rules — 1 obligation

| ID | Statement | Triggers |
|---|---|---|
| `COD-010` | The `EXTCODEHASH` of every visited address, entity, and referenced library must be unchanged between the first and second validation | `external_call_in_validation`, `delegatecall_in_validation` |

Checkable by taking the code hash of every address touched during simulation and re-checking at bundle time. This is one of the few rules where your two-phase model gives you something a single-shot analyser cannot get.

## B1.4 Paymaster-specific rules — 3 obligations

These sit under EREP in the standard but are genuinely contract properties, not bundler bookkeeping.

| ID | Statement | Triggers |
|---|---|---|
| `EREP-050` | An unstaked paymaster must not return a non-empty `context` | `postop_handler` + `paymaster_role` |
| `EREP-055` | Context size must not change between validation and bundle creation | `postop_handler` |
| `EREP-070` | A staked entity must not reduce its validation gas by more than 10% between the second validation and bundle creation | `paymaster_role` \| `factory_role` |

`EREP-050` is worth highlighting: a paymaster that returns context without a stake is silently unusable, and this is a common real defect. It is also trivially checkable — does `validatePaymasterUserOp` ever return non-empty bytes, and is the paymaster staked.

## B1.5 Limits — 2 obligations

| ID | Statement | Triggers |
|---|---|---|
| `LIM-020` | A paymaster's returned `context` must not exceed `MAX_CONTEXT_SIZE` (2048 bytes) | `postop_handler` |
| `LIM-030` | `verificationGasLimit` and `paymasterVerificationGasLimit` must exceed actual validation usage by `VALIDATION_GAS_SLACK` (4000) | any validation entry point |

`LIM-010`, `LIM-040`, `LIM-050` are operation- and bundle-size limits, not contract properties. Excluded.

## B1.6 Delegation rules — 3 obligations

| ID | Statement | Triggers |
|---|---|---|
| `AUTH-020` | An account with EIP-7702 delegation may only be the sender, never another entity | `eip7702_delegated` |
| `AUTH-030` | A delegated account may be accessed via `*CALL`/`EXTCODE*` only if it is the sender of the current operation | `eip7702_delegated`, `external_call_in_validation` |
| `STO-040` (partial) | An address used as factory, paymaster, or aggregator must not also serve as an account | `paymaster_role` + `account_role` on the same contract |

`AUTH-010` and `AUTH-040` are mempool-level and excluded. `STO-040` is included in its statically checkable form only — does this contract implement both roles.

---

**B1 total: 24 obligations.**

Distribution by mechanism, which is what makes selection non-trivial: a plain owner account triggers roughly 8; a paymaster with `postOp` triggers roughly 16; a modular account making external calls during validation triggers roughly 20.

---

# B2 — Dispersed obligations (`O_D`)

These are not numbered anywhere. Each entry needs a source URL and commit. Organised by triggering mechanism, which is also the trigger-map structure from Step C2.

## B2.1 `local_digest` — 8 obligations

Fires when the contract computes its own hash and passes it to signature recovery, instead of using the `userOpHash` parameter.

| ID | Obligation | Where documented |
|---|---|---|
| `DIG-001` | A self-computed digest must commit to `block.chainid` | ERC-4337 `getUserOpHash`; cross-chain replay findings |
| `DIG-002` | must commit to the EntryPoint address | ERC-4337 `getUserOpHash` |
| `DIG-003` | must commit to `op.nonce` | ERC-4337; replay findings |
| `DIG-004` | must commit to `op.sender` | audit findings on shared-signer wallets |
| `DIG-005` | must commit to the full `callData`, not a prefix or selector | audit findings |
| `DIG-006` | must commit to gas fields where the signer's cost exposure depends on them | paymaster audit findings |
| `DIG-007` | should use EIP-712 domain separation rather than raw `keccak256(abi.encode(...))` | EIP-712; audit recommendations |
| `DIG-008` | `abi.encodePacked` with two or more variable-length arguments is forbidden in digest construction (hash collision) | Solidity docs; recurring audit finding |

`DIG-008` is worth including specifically because it is a mechanism-triggered obligation with a long audit history outside account abstraction, which demonstrates the cross-domain transfer your corpus design depends on.

## B2.2 `delegated_key_set` — 7 obligations

Fires on a `mapping(address => bool|struct)` read on a path that returns validation success.

| ID | Obligation |
|---|---|
| `SES-001` | A delegated key must be restricted to a set of permitted target addresses |
| `SES-002` | A delegated key must be restricted to a set of permitted function selectors |
| `SES-003` | A delegated key must have a value or spend cap |
| `SES-004` | A delegated key must have an expiry, expressed through packed `validationData`, not `block.timestamp` |
| `SES-005` | Key revocation must take effect immediately, including for already-signed operations |
| `SES-006` | A delegated key must not be able to install another key, upgrade the account, or change the owner |
| `SES-007` | Policy must be enforced against the decoded execution target, including every element of a batch, not only the outer call |

`SES-004` is where B1 and B2 interlock: the obligation is "have an expiry", and satisfying it naively by reading `block.timestamp` violates `OP-011`. A contract can fail B2 by omission or fail B1 by fixing it the obvious wrong way. That interaction is a good motivating example for the paper.

`SES-007` is the batch case: a policy check on `execute(target, ...)` that does not quantify over `executeBatch` elements is a real and common defect.

## B2.3 `consumed_set` + `postop_handler` — 4 obligations

| ID | Obligation |
|---|---|
| `ORD-001` | A one-shot resource must be marked consumed during validation, not in `postOp`, because all validations in a bundle precede all executions |
| `ORD-002` | `postOp` must handle `PostOpMode.postOpReverted` without reverting again |
| `ORD-003` | State that validation depends on must not be written only in `postOp` |
| `ORD-004` | `postOp` must not assume the operation succeeded; refund and accounting logic must branch on mode |

`ORD-001` is your `SIM` class and it is the obligation with no single-call meaning at all.

## B2.4 `paymaster_role` — 8 obligations

| ID | Obligation |
|---|---|
| `PAY-001` | A sponsorship authorisation must bind `op.sender` |
| `PAY-002` | must bind `block.chainid` |
| `PAY-003` | must bind this paymaster's own address |
| `PAY-004` | must bind or bound `maxCost` |
| `PAY-005` | must carry a time window, returned as packed `validationData` |
| `PAY-006` | must be single-use, enforced during validation (see `ORD-001`) |
| `PAY-007` | A token paymaster must reject a stale or manipulable price source |
| `PAY-008` | A paymaster must maintain a deposit sufficient for outstanding sponsorship, and must not allow deposit drain via unbounded sponsorship |

## B2.5 `webauthn_verifier` — 6 obligations

Sourced primarily from the W3C WebAuthn specification and CertiK's passkey wallet analysis, which is the fullest public statement of these.

| ID | Obligation |
|---|---|
| `WEB-001` | Verify that `clientDataJSON.type` is `webauthn.get`, so an authentication assertion cannot be substituted for a registration ceremony |
| `WEB-002` | Verify that `clientDataJSON.challenge` equals the `userOpHash` being authorised |
| `WEB-003` | Verify the signature over `authenticatorData ‖ SHA256(clientDataJSON)` in that exact order |
| `WEB-004` | Verify that `r` and `s` lie in `[1, n-1]` (the Psychic Signatures class) |
| `WEB-005` | Enforce low-`s` or otherwise reject the malleable second signature |
| `WEB-006` | Check the user-presence and user-verification flags in `authenticatorData` |

`WEB-001` and `WEB-002` are the pair CertiK identifies as the recurring real-world failure: the cryptography is correct and the surrounding ceremony binding is not.

## B2.6 `module_installation` (ERC-7579) — 6 obligations

| ID | Obligation |
|---|---|
| `MOD-001` | Validator and executor module types must be distinguished; a validator must not be installable as an executor |
| `MOD-002` | Module installation should be gated by attestation (ERC-7484) or an equivalent allowlist |
| `MOD-003` | A hook reverting in `preCheck` or `postCheck` must not permanently brick the account |
| `MOD-004` | A fallback handler must be invoked via `call` or `staticcall` and must append the original `msg.sender` per ERC-2771 |
| `MOD-005` | Validator selection must not be attacker-controllable; the nonce key or selector determining which validator runs must be authenticated |
| `MOD-006` | Uninstalling the last validator must be prevented, or the account becomes unrecoverable |

`MOD-005` is notable because ERC-7579 explicitly declines to specify validator selection, so the obligation exists while the standard is silent — exactly the case your retrieval argument depends on.

## B2.7 `entrypoint_digest` and general signature — 5 obligations

| ID | Obligation |
|---|---|
| `SIG-001` | `ecrecover` returning `address(0)` must be rejected explicitly |
| `SIG-002` | Signature malleability (high-`s`, or `v` not in `{27,28}`) must be rejected |
| `SIG-003` | A signature must not be replayable across accounts sharing an owner |
| `SIG-004` | ERC-1271 `isValidSignature` must return the magic value only on success, never on a revert path |
| `SIG-005` | Counterfactual signature validation should follow ERC-6492 rather than assuming deployment |

## B2.8 `prefund_path` — 3 obligations

| ID | Obligation |
|---|---|
| `PRE-001` | `missingAccountFunds` must be paid without reverting on zero |
| `PRE-002` | The prefund transfer's return value must be handled, or deliberately ignored with a comment, not silently dropped |
| `PRE-003` | Prefund payment must not be conditional on validation outcome in a way that lets a failed validation escape payment |

---

**B2 total: 47 obligations across 8 mechanisms.**

Combined inventory: **71 obligations**. That is within the 60–120 target and large enough that per-contract applicable sets differ substantially, which is what P1 needs.

---

## Expected applicable-set sizes

Sanity check on P1 before you label anything. Approximate counts per contract type:

| Contract type | B1 | B2 | Total |
|---|---|---|---|
| Owner-only account (ECDSA, EntryPoint digest) | 8 | 8 | ~16 |
| Session-key account | 10 | 15 | ~25 |
| Passkey account | 10 | 14 | ~24 |
| ERC-7579 modular account | 18 | 17 | ~35 |
| Coupon paymaster with `postOp` | 16 | 12 | ~28 |
| Token paymaster with oracle | 18 | 13 | ~31 |

Owner-only versus passkey share the B1 opcode and storage baseline but almost nothing in B2 — the ECDSA obligations (`SIG-001`, `SIG-002`) and the WebAuthn obligations (`WEB-001`…`WEB-006`) are disjoint. That disjointness is what will produce a high δ in Step D3.

---

## Format for both sets

Every entry, B1 and B2 alike:

```python
Obligation(
    id="SES-004",
    statement="A delegated key must have an expiry expressed through packed "
              "validationData rather than a block.timestamp comparison.",
    triggers=frozenset({"delegated_key_set"}),
    scope=frozenset({"0.6", "0.7", "0.8"}),
    authority=Authority(modal="MUST", corroboration=3, specificity="field-level"),
    sources=("AUD-C4-2023-XX-042", "ERC7562-OP-011", "DOC-KERNEL-SESSIONKEY"),
    kind=ObligationKind.POLICY,
    stream=Stream.RETRIEVED,
    conflicts_with=(),
)
```

B1 entries carry `stream=COMPILED` and an empty `sources`, because they are transcribed rather than retrieved. B2 entries must have at least one source with a URL and commit hash recorded alongside.

---

## Two things to get right while building this

**Do not let B2 entries name benchmark variables.** `SES-001` says "a set of permitted target addresses", never `allowedTarget`. The moment an obligation names a benchmark identifier, the rename-invariance test from Step A4 becomes meaningless for that obligation.

**Record the date each B2 entry was added.** Entries added after benchmark construction must be marked, because an inventory written while looking at the contracts you evaluate on is not an inventory, it is an answer key. This is the same discipline as the trigger map in Step C2, and for the same reason.

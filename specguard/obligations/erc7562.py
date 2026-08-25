# SPDX-License-Identifier: MIT
"""
Compiled ERC-7562 Obligation Rule Set (O_Sigma) for SpecGuard-AA (Step B1).
Hand-transcribed normative rule table from ERC-7562 (ethereum/ERCs).
SelectRules(mechanisms, version) performs pure deterministic lookup with no LLM calls.
"""

from typing import List, Set
from specguard.models import MechanismTag
from specguard.obligations.models import (
    Obligation,
    ObligationKind,
    Stream,
    Authority,
)
from specguard.obligations.authority import compute_authority


COMPILED_ERC7562_RULES: List[Obligation] = [
    # B1.1 Opcode rules
    Obligation(
        id="OP-011",
        statement="Validation must not execute ORIGIN, GASPRICE, BLOCKHASH, COINBASE, TIMESTAMP, NUMBER, PREVRANDAO, GASLIMIT, BASEFEE, BLOBHASH, BLOBBASEFEE, CREATE, INVALID, SELFDESTRUCT",
        triggers={"validation_entrypoint"},
        scope={"0.6", "0.7", "0.8"},
        authority=compute_authority("MUST", 5, "opcode-level"),
        sources=["ERC7562-OP-011"],
        kind=ObligationKind.FORBIDDEN_OPCODE,
        stream=Stream.COMPILED,
    ),
    Obligation(
        id="OP-012",
        statement="GAS is permitted only when immediately followed by a *CALL opcode",
        triggers={"validation_entrypoint"},
        scope={"0.6", "0.7", "0.8"},
        authority=compute_authority("MUST", 5, "opcode-level"),
        sources=["ERC7562-OP-012"],
        kind=ObligationKind.FORBIDDEN_OPCODE,
        stream=Stream.COMPILED,
    ),
    Obligation(
        id="OP-013",
        statement="Validation must not execute any unassigned or invalid EVM opcode",
        triggers={"validation_entrypoint"},
        scope={"0.6", "0.7", "0.8"},
        authority=compute_authority("MUST", 5, "opcode-level"),
        sources=["ERC7562-OP-013"],
        kind=ObligationKind.FORBIDDEN_OPCODE,
        stream=Stream.COMPILED,
    ),
    Obligation(
        id="OP-020",
        statement="Validation execution must not revert with out-of-gas error",
        triggers={"validation_entrypoint"},
        scope={"0.6", "0.7", "0.8"},
        authority=compute_authority("MUST", 5, "field-level"),
        sources=["ERC7562-OP-020"],
        kind=ObligationKind.STORAGE_SCOPE,
        stream=Stream.COMPILED,
    ),
    Obligation(
        id="OP-041",
        statement="Validation must not EXTCODE* or *CALL an address with no deployed code",
        triggers={"external_call_in_validation"},
        scope={"0.6", "0.7", "0.8"},
        authority=compute_authority("MUST", 5, "field-level"),
        sources=["ERC7562-OP-041"],
        kind=ObligationKind.STORAGE_SCOPE,
        stream=Stream.COMPILED,
    ),
    Obligation(
        id="OP-051_055",
        statement="Access to EntryPoint address during validation is limited to EXTCODESIZE ISZERO, depositTo(sender), fallback from sender, and incrementNonce() from sender",
        triggers={"external_call_in_validation"},
        scope={"0.6", "0.7", "0.8"},
        authority=compute_authority("MUST", 5, "field-level"),
        sources=["ERC7562-OP-051"],
        kind=ObligationKind.STORAGE_SCOPE,
        stream=Stream.COMPILED,
    ),
    Obligation(
        id="OP-061",
        statement="CALL with non-zero value is forbidden during validation, except to the EntryPoint",
        triggers={"external_call_in_validation"},
        scope={"0.6", "0.7", "0.8"},
        authority=compute_authority("MUST", 5, "field-level"),
        sources=["ERC7562-OP-061"],
        kind=ObligationKind.STORAGE_SCOPE,
        stream=Stream.COMPILED,
    ),
    Obligation(
        id="OP-062",
        statement="Only core precompiles 0x01-0x11 and accepted RIP-7212 secp256r1 precompiles may be called during validation",
        triggers={"external_call_in_validation", "webauthn_verifier"},
        scope={"0.6", "0.7", "0.8"},
        authority=compute_authority("MUST", 5, "field-level"),
        sources=["ERC7562-OP-062"],
        kind=ObligationKind.FORBIDDEN_OPCODE,
        stream=Stream.COMPILED,
    ),
    Obligation(
        id="OP-070",
        statement="Transient storage (TLOAD/TSTORE) is treated exactly as persistent storage for all validation storage rules",
        triggers={"validation_entrypoint"},
        scope={"0.7", "0.8"},
        authority=compute_authority("MUST", 5, "opcode-level"),
        sources=["ERC7562-OP-070"],
        kind=ObligationKind.STORAGE_SCOPE,
        stream=Stream.COMPILED,
    ),
    Obligation(
        id="OP-080",
        statement="BALANCE and SELFBALANCE are permitted during validation only from a staked entity",
        triggers={"validation_entrypoint"},
        scope={"0.6", "0.7", "0.8"},
        authority=compute_authority("MUST", 5, "opcode-level"),
        sources=["ERC7562-OP-080"],
        kind=ObligationKind.FORBIDDEN_OPCODE,
        stream=Stream.COMPILED,
    ),

    # B1.2 Storage rules
    Obligation(
        id="STO-010",
        statement="Access to the account's own storage is always permitted during validation",
        triggers={"validation_entrypoint"},
        scope={"0.6", "0.7", "0.8"},
        authority=compute_authority("MUST", 5, "field-level"),
        sources=["ERC7562-STO-010"],
        kind=ObligationKind.STORAGE_SCOPE,
        stream=Stream.COMPILED,
    ),
    Obligation(
        id="STO-021",
        statement="Associated storage of the account in an external contract is permitted when the account already exists",
        triggers={"external_call_in_validation"},
        scope={"0.6", "0.7", "0.8"},
        authority=compute_authority("MUST", 5, "field-level"),
        sources=["ERC7562-STO-021"],
        kind=ObligationKind.STORAGE_SCOPE,
        stream=Stream.COMPILED,
    ),
    Obligation(
        id="STO-022",
        statement="Associated storage of the account in an external contract is permitted with initCode only when the factory is staked",
        triggers={"external_call_in_validation"},
        scope={"0.6", "0.7", "0.8"},
        authority=compute_authority("MUST", 5, "field-level"),
        sources=["ERC7562-STO-022"],
        kind=ObligationKind.STORAGE_SCOPE,
        stream=Stream.COMPILED,
    ),
    Obligation(
        id="STO-031",
        statement="A staked entity may access its own storage during validation",
        triggers={"postop_handler"},
        scope={"0.6", "0.7", "0.8"},
        authority=compute_authority("MUST", 5, "field-level"),
        sources=["ERC7562-STO-031"],
        kind=ObligationKind.STORAGE_SCOPE,
        stream=Stream.COMPILED,
    ),
    Obligation(
        id="STO-032",
        statement="A staked entity may read and write slots associated with itself in any non-entity contract",
        triggers={"postop_handler"},
        scope={"0.6", "0.7", "0.8"},
        authority=compute_authority("MUST", 5, "field-level"),
        sources=["ERC7562-STO-032"],
        kind=ObligationKind.STORAGE_SCOPE,
        stream=Stream.COMPILED,
    ),
    Obligation(
        id="STO-033",
        statement="A staked entity has read-only access to any storage in a non-entity contract during validation",
        triggers={"postop_handler"},
        scope={"0.6", "0.7", "0.8"},
        authority=compute_authority("MUST", 5, "field-level"),
        sources=["ERC7562-STO-033"],
        kind=ObligationKind.STORAGE_SCOPE,
        stream=Stream.COMPILED,
    ),

    # B1.3 Code rules
    Obligation(
        id="COD-010",
        statement="The EXTCODEHASH of every visited address, entity, and referenced library must be unchanged between first and second validation",
        triggers={"external_call_in_validation"},
        scope={"0.6", "0.7", "0.8"},
        authority=compute_authority("MUST", 5, "field-level"),
        sources=["ERC7562-COD-010"],
        kind=ObligationKind.COMMITMENT,
        stream=Stream.COMPILED,
    ),

    # B1.4 Paymaster-specific rules
    Obligation(
        id="EREP-050",
        statement="An unstaked paymaster must not return a non-empty context from validatePaymasterUserOp",
        triggers={"postop_handler"},
        scope={"0.6", "0.7", "0.8"},
        authority=compute_authority("MUST", 5, "field-level"),
        sources=["ERC7562-EREP-050"],
        kind=ObligationKind.POLICY,
        stream=Stream.COMPILED,
    ),
    Obligation(
        id="EREP-055",
        statement="Context size returned by paymaster must not change between validation and bundle creation",
        triggers={"postop_handler"},
        scope={"0.6", "0.7", "0.8"},
        authority=compute_authority("MUST", 5, "field-level"),
        sources=["ERC7562-EREP-055"],
        kind=ObligationKind.COMMITMENT,
        stream=Stream.COMPILED,
    ),
    Obligation(
        id="EREP-070",
        statement="A staked entity must not reduce its validation gas by more than 10% between second validation and bundle creation",
        triggers={"postop_handler"},
        scope={"0.6", "0.7", "0.8"},
        authority=compute_authority("MUST", 5, "field-level"),
        sources=["ERC7562-EREP-070"],
        kind=ObligationKind.POLICY,
        stream=Stream.COMPILED,
    ),

    # B1.5 Limits
    Obligation(
        id="LIM-020",
        statement="A paymaster's returned context must not exceed MAX_CONTEXT_SIZE (2048 bytes)",
        triggers={"postop_handler"},
        scope={"0.6", "0.7", "0.8"},
        authority=compute_authority("MUST", 5, "field-level"),
        sources=["ERC7562-LIM-020"],
        kind=ObligationKind.POLICY,
        stream=Stream.COMPILED,
    ),
    Obligation(
        id="LIM-030",
        statement="verificationGasLimit must exceed actual validation gas usage by VALIDATION_GAS_SLACK (4000 gas)",
        triggers={"validation_entrypoint"},
        scope={"0.6", "0.7", "0.8"},
        authority=compute_authority("MUST", 5, "field-level"),
        sources=["ERC7562-LIM-030"],
        kind=ObligationKind.POLICY,
        stream=Stream.COMPILED,
    ),

    # B1.6 Delegation rules
    Obligation(
        id="AUTH-020",
        statement="An account with EIP-7702 delegation may only be the sender, never another entity in a UserOp",
        triggers={"validation_entrypoint"},
        scope={"0.8"},
        authority=compute_authority("MUST", 5, "field-level"),
        sources=["ERC7562-AUTH-020"],
        kind=ObligationKind.POLICY,
        stream=Stream.COMPILED,
    ),
    Obligation(
        id="STO-040",
        statement="An address used as factory, paymaster, or aggregator must not also serve as an account contract",
        triggers={"postop_handler"},
        scope={"0.6", "0.7", "0.8"},
        authority=compute_authority("MUST", 5, "field-level"),
        sources=["ERC7562-STO-040"],
        kind=ObligationKind.POLICY,
        stream=Stream.COMPILED,
    ),
]


def SelectRules(
    mechanism_tags: List[MechanismTag],
    protocol_version: str = "0.7",
) -> List[Obligation]:
    """
    Deterministic rule selection function SelectRules(Sigma, mechanisms).
    Matches compiled ERC-7562 rules against detected contract mechanisms and version scope.
    Zero model / LLM calls.
    """
    active_tag_names: Set[str] = {m.tag for m in mechanism_tags}
    # Always include baseline validation entrypoint trigger
    active_tag_names.add("validation_entrypoint")

    selected: List[Obligation] = []
    for rule in COMPILED_ERC7562_RULES:
        # Version check
        if protocol_version not in rule.scope:
            continue
        # Trigger intersection check
        if rule.triggers.intersection(active_tag_names):
            selected.append(rule)

    return selected

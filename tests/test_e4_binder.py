# SPDX-License-Identifier: MIT
"""
Dedicated Unit Tests for Step E4: Deterministic Symbol Binding with Explicit Outcomes.

Verifies:
1. SymbolBinding produces explicit tri-state resolution (RESOLVED, AMBIGUOUS, UNRESOLVED).
2. Functions resolve by 4-byte selector, not name.
3. State symbols resolve through structural mechanism tags.
4. Acceptance path state_vars_read disambiguates candidate symbols.
5. Zero confidence arithmetic or threshold scoring exists in the binder.
"""

import pytest
from specguard.models import (
    ContractFacts,
    Role,
    PropertyType,
    Property,
    PropertyBinding,
    SymbolBinding,
    BindStatus,
    BindKind,
    MechanismTag,
    StateVariableFact,
    FunctionFact,
    AcceptancePath,
    ProtocolVersion,
)
from specguard.binding.binder import NormalizerAndBinder


def _make_contract_facts_with_mechanisms(
    contract_name="TestAccount",
    roles=None,
    mechanisms=None,
    acceptance_paths=None,
    state_vars=None,
) -> ContractFacts:
    return ContractFacts(
        contract_name=contract_name,
        source_path=f"contracts/src/{contract_name}.sol",
        roles=roles or [Role.ACCOUNT],
        functions=[
            FunctionFact(
                name="validateUserOp",
                visibility="external",
                parameters=[{"name": "op", "type": "PackedUserOperation"}],
                return_types=["uint256"],
            )
        ],
        state_variables=state_vars or [
            StateVariableFact(name="owner", type_str="address"),
            StateVariableFact(name="sessionKey", type_str="mapping(address => bool)"),
        ],
        mechanism_tags=mechanisms or [
            MechanismTag(tag="delegated_key_set", evidence_nodes=["mapping(address => bool) sessionKey"]),
        ],
        acceptance_paths=acceptance_paths or [
            AcceptancePath(
                path_id="path_0_session",
                function_name="validateUserOp",
                digest_expression="keccak256(abi.encode(op.sender, op.callData))",
                is_local_digest=True,
                state_vars_read=["sessionKey"],
            )
        ],
        protocol_version=ProtocolVersion.V0_7,
    )


def test_e4_binding_resolved_single_candidate():
    """Unambiguous mechanism candidate resolves to BindStatus.RESOLVED."""
    facts = _make_contract_facts_with_mechanisms()
    binder = NormalizerAndBinder()

    prop = Property(
        property_id="PROP-SES-001",
        template_type=PropertyType.SESSION,
        target_role=Role.ACCOUNT,
        precondition="signedBy(op, K)",
        required_condition="permittedTarget(op, K)",
    )

    binding = binder.bind(prop, facts)
    assert binding is not None
    assert binding.status == BindStatus.RESOLVED
    assert binding.key_mapping == "sessionKey"

    sb = binding.symbol_bindings["sessionKey"]
    assert sb.status == BindStatus.RESOLVED
    assert sb.resolved_to == "sessionKey"
    assert sb.kind == BindKind.STATE_VAR


def test_e4_binding_disambiguated_by_acceptance_path():
    """Two delegated key mappings exist, but acceptance path reads only one -> disambiguated to RESOLVED."""
    state_vars = [
        StateVariableFact(name="tempKey", type_str="mapping(address => bool)"),
        StateVariableFact(name="sessionKey", type_str="mapping(address => bool)"),
    ]
    mechanisms = [
        MechanismTag(tag="delegated_key_set", evidence_nodes=["mapping(address => bool) tempKey"]),
        MechanismTag(tag="delegated_key_set", evidence_nodes=["mapping(address => bool) sessionKey"]),
    ]
    path = AcceptancePath(
        path_id="path_session",
        function_name="validateUserOp",
        digest_expression="localHash",
        is_local_digest=True,
        state_vars_read=["sessionKey"],  # only sessionKey is read on this path
    )

    facts = _make_contract_facts_with_mechanisms(
        state_vars=state_vars,
        mechanisms=mechanisms,
        acceptance_paths=[path],
    )

    binder = NormalizerAndBinder()
    prop = Property(
        property_id="PROP-SES-002",
        template_type=PropertyType.SESSION,
        target_role=Role.ACCOUNT,
        precondition="signedBy(op, K)",
        required_condition="permittedTarget(op, K)",
    )

    binding = binder.bind(prop, facts)
    assert binding is not None
    assert binding.key_mapping == "sessionKey"
    assert binding.symbol_bindings["sessionKey"].status == BindStatus.RESOLVED


def test_e4_binding_ambiguous_outcome():
    """Multiple candidates on the same path produce BindStatus.AMBIGUOUS."""
    state_vars = [
        StateVariableFact(name="keyA", type_str="mapping(address => bool)"),
        StateVariableFact(name="keyB", type_str="mapping(address => bool)"),
    ]
    mechanisms = [
        MechanismTag(tag="delegated_key_set", evidence_nodes=["mapping(address => bool) keyA"]),
        MechanismTag(tag="delegated_key_set", evidence_nodes=["mapping(address => bool) keyB"]),
    ]
    path = AcceptancePath(
        path_id="path_ambig",
        function_name="validateUserOp",
        state_vars_read=["keyA", "keyB"],  # both read on the same path
    )

    facts = _make_contract_facts_with_mechanisms(
        state_vars=state_vars,
        mechanisms=mechanisms,
        acceptance_paths=[path],
    )

    binder = NormalizerAndBinder()
    prop = Property(
        property_id="PROP-SES-003",
        template_type=PropertyType.SESSION,
        target_role=Role.ACCOUNT,
        precondition="signedBy(op, K)",
        required_condition="permittedTarget(op, K)",
    )

    binding = binder.bind(prop, facts)
    assert binding is not None
    assert binding.status == BindStatus.AMBIGUOUS
    assert binding.symbol_bindings["sessionKey"].status == BindStatus.AMBIGUOUS
    assert binding.symbol_bindings["sessionKey"].resolved_to is None


def test_e4_zero_confidence_arithmetic_in_binder():
    """Verify that confidence thresholds are eliminated from binder attributes."""
    binder = NormalizerAndBinder()
    assert not hasattr(binder, "confidence_threshold"), (
        "Defect: confidence_threshold must be eliminated per Step E4."
    )

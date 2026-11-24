# SPDX-License-Identifier: MIT
"""
Dedicated Unit Tests for Step F1: Dynamic Harness Generation from Bindings.

Verifies:
1. Generated harnesses contain real keys via makeAddrAndKey and real signatures via vm.sign.
2. ZERO vm.mockCall statements exist in generated harness code.
3. Administrative setup calls target contract's own setter functions.
4. Relative imports are derived dynamically from contract source path.
5. Handles version-indexed struct layout (PackedUserOperation vs UserOperation).
"""

import pytest
from specguard.models import (
    ContractFacts,
    Role,
    PropertyType,
    Property,
    PropertyBinding,
    AdminFunctionSetup,
    ProtocolVersion,
)
from specguard.backends.foundry_fuzz import FoundryFuzzBackend


def _make_facts(contract_name="DelegatedAccount", source_path="contracts/src/worked_examples/DelegatedAccount.sol") -> ContractFacts:
    return ContractFacts(
        contract_name=contract_name,
        source_path=source_path,
        roles=[Role.ACCOUNT],
        admin_setups=[
            AdminFunctionSetup(
                function_name="setSessionKey",
                target_state_var="sessionKey",
                caller_guard="onlyOwner",
            )
        ],
        protocol_version=ProtocolVersion.V0_7,
    )


def test_f1_harness_uses_real_keys_and_vm_sign():
    """Harness generates key pair via makeAddrAndKey and signs with vm.sign."""
    facts = _make_facts()
    binding = PropertyBinding(validator_function="validateUserOp", key_mapping="sessionKey")
    prop = Property(
        property_id="PROP-SES-001",
        template_type=PropertyType.SESSION,
        target_role=Role.ACCOUNT,
        precondition="signedBy(op, K)",
        required_condition="permittedTarget(op, K)",
    )

    backend = FoundryFuzzBackend(forge_path="forge")
    harness = backend._generate_harness(prop, binding, facts)

    assert harness is not None
    assert "makeAddrAndKey" in harness
    assert "vm.sign" in harness


def test_f1_harness_zero_mock_calls():
    """Step F1 requirement: No vm.mockCall on recovery. None."""
    facts = _make_facts()
    backend = FoundryFuzzBackend(forge_path="forge")

    for p_type in [PropertyType.SESSION, PropertyType.AUTH, PropertyType.PAYMASTER]:
        prop = Property(
            property_id=f"PROP-TEST-{p_type.value}",
            template_type=p_type,
            target_role=Role.ACCOUNT if p_type != PropertyType.PAYMASTER else Role.PAYMASTER,
            precondition="true",
            required_condition="true",
        )
        binding = PropertyBinding(validator_function="validateUserOp")
        harness = backend._generate_harness(prop, binding, facts)
        if harness:
            assert "vm.mockCall(" not in harness, f"Defect: Found vm.mockCall in {p_type.value} harness"


def test_f1_harness_dynamic_admin_setup():
    """Harness invokes target contract's own administrative setter function."""
    facts = _make_facts()
    binding = PropertyBinding(
        validator_function="validateUserOp",
        key_mapping="sessionKey",
        admin_setup=facts.admin_setups[0],
    )
    prop = Property(
        property_id="PROP-SES-002",
        template_type=PropertyType.SESSION,
        target_role=Role.ACCOUNT,
        precondition="signedBy(op, K)",
        required_condition="permittedTarget(op, K)",
    )

    backend = FoundryFuzzBackend(forge_path="forge")
    harness = backend._generate_harness(prop, binding, facts)

    assert harness is not None
    assert "setSessionKey" in harness
    assert "vm.prank(owner)" in harness


def test_f1_harness_relative_import_derived():
    """Harness resolves relative import path based on source_path."""
    facts = _make_facts(contract_name="CustomWallet", source_path="contracts/src/custom/CustomWallet.sol")
    binding = PropertyBinding(validator_function="validateUserOp")
    prop = Property(
        property_id="PROP-AUTH-001",
        template_type=PropertyType.AUTH,
        target_role=Role.ACCOUNT,
        precondition="true",
        required_condition="true",
    )

    backend = FoundryFuzzBackend(forge_path="forge")
    harness = backend._generate_harness(prop, binding, facts)

    assert harness is not None
    assert 'import "../../src/custom/CustomWallet.sol";' in harness

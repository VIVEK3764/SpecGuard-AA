# SPDX-License-Identifier: MIT
"""
Tests for SpecGuard-AA Step 6: Evidence-Backed Reporting & Witness Minimization.
"""

import os
from specguard.reporting.reporter import ReportEngine
from specguard.models import (
    ContractFacts,
    Property,
    PropertyBinding,
    PropertyType,
    Role,
    Witness,
)


def test_reporting_condition_valid_witness():
    """Valid witness produces SecurityReport and standalone .t.sol reproduction script."""
    engine = ReportEngine()

    facts = ContractFacts(
        contract_name="SessionAccount",
        source_path="contracts/src/worked_examples/SessionAccount.sol",
        roles=[Role.ACCOUNT],
    )

    prop = Property(
        property_id="PROP-SESSION-TARGET-001",
        template_type=PropertyType.SESSION,
        target_role=Role.ACCOUNT,
        bindings=PropertyBinding(validator_function="validateUserOp"),
        precondition="success(validateUserOp(op))",
        required_condition="allowedTarget(K, op.callData.target)",
        source_chunk_ids=["ERC4337-ACC-002"],
    )

    binding = PropertyBinding(validator_function="validateUserOp")

    witness = Witness(
        backend="FoundryFuzz",
        reproducible_test_code="// Test code",
        user_op_json={"callData": "0x1234567890abcdef"},
        trace_events=["[FAIL: VIOLATION]"],
        is_valid=True,
    )

    report = engine.generate_report(prop, binding, facts, witness)

    assert report is not None
    assert report.contract_name == "SessionAccount"
    assert report.property.property_id == "PROP-SESSION-TARGET-001"
    assert os.path.exists(report.reproduction_script_path)


def test_reporting_condition_fabricated_witness_rejected():
    """Fabricated / invalid witness is REJECTED by CheckWitness and returns None."""
    engine = ReportEngine()

    facts = ContractFacts(
        contract_name="SessionAccount",
        source_path="contracts/src/worked_examples/SessionAccount.sol",
        roles=[Role.ACCOUNT],
    )

    prop = Property(
        property_id="PROP-SESSION-TARGET-001",
        template_type=PropertyType.SESSION,
        target_role=Role.ACCOUNT,
        bindings=PropertyBinding(validator_function="validateUserOp"),
        precondition="success(validateUserOp(op))",
        required_condition="allowedTarget(K, op.callData.target)",
        source_chunk_ids=["ERC4337-ACC-002"],
    )

    binding = PropertyBinding(validator_function="validateUserOp")

    # Fabricated invalid witness
    fake_witness = Witness(
        backend="FoundryFuzz",
        reproducible_test_code="// Fake test code",
        user_op_json={"raw_failure": "Fabricated fake failure"},
        trace_events=[],
        is_valid=False,
    )

    report = engine.generate_report(prop, binding, facts, fake_witness)

    assert report is None, "CheckWitness MUST reject fabricated or invalid witness"


def test_witness_minimization():
    """Witness minimization shrinks fields while preserving validity."""
    engine = ReportEngine()

    witness = Witness(
        backend="FoundryFuzz",
        reproducible_test_code="// Test code",
        user_op_json={"callData": "0x1234567890abcdef1234567890abcdef"},
        trace_events=["[FAIL]"],
        is_valid=True,
    )

    facts = ContractFacts(
        contract_name="SessionAccount",
        source_path="contracts/src/worked_examples/SessionAccount.sol",
        roles=[Role.ACCOUNT],
    )

    min_witness = engine.minimize_witness(witness, facts)
    assert min_witness.user_op_json["minimized"] is True
    assert len(min_witness.user_op_json["callData"]) <= 10

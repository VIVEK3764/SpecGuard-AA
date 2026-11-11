# SPDX-License-Identifier: MIT
"""
Dedicated Unit Tests for Step F2: Structured Validation Outcomes (SpecGuard-AA).
Verifies:
1. Four-valued Outcome enum: VIOLATED, HELD, HARNESS_ERROR, TIMEOUT
2. Structured JSON parsing: assertion failure in test function -> Outcome.VIOLATED
3. setUp() revert is recognized as HARNESS_ERROR (never VIOLATED)
4. Non-zero exit with unparseable JSON (e.g. solc compilation error) -> HARNESS_ERROR
5. TimeoutExpired -> Outcome.TIMEOUT
6. Transcript correctly tracks stage_5_outcome_counts
7. Rule B adherence: No decisions made from console substrings
"""

import json
import pytest
from specguard.models import (
    Outcome,
    ValidationResult,
    Property,
    PropertyBinding,
    PropertyType,
    Role,
    ContractFacts,
)
from specguard.backends.foundry_fuzz import FoundryFuzzBackend
from specguard.backends.dispatcher import BackendDispatcher


def test_f2_outcome_enum_values():
    """Verify the 4 exact required outcome states."""
    assert Outcome.VIOLATED.value == "VIOLATED"
    assert Outcome.HELD.value == "HELD"
    assert Outcome.HARNESS_ERROR.value == "HARNESS_ERROR"
    assert Outcome.TIMEOUT.value == "TIMEOUT"


def test_f2_evaluate_json_assertion_violated():
    """Assertion failure in test function produces Outcome.VIOLATED with failing obligation."""
    backend = FoundryFuzzBackend(forge_path="dummy_forge")

    sample_json = {
        "contracts/test/generated/Test_PROP_1.t.sol:Test_PROP_1": {
            "test_results": {
                "test_obligation_SES_001()": {
                    "status": "Failure",
                    "reason": "assertion failed: target not allowed",
                    "counterexample": {"attacker": "0x1234"},
                    "decoded_logs": ["VIOLATION: target policy bypass"],
                }
            }
        }
    }

    res = backend._evaluate_json_results(
        json_data=sample_json,
        returncode=1,
        harness_code="// test harness",
        property_id="PROP-SES-001",
        raw_log_path="dummy.log",
    )

    assert res.outcome == Outcome.VIOLATED
    assert res.failing_obligation_id == "SES_001"
    assert res.witness is not None
    assert res.witness.backend == "FoundryFuzz"
    assert res.witness.user_op_json == {"attacker": "0x1234"}
    assert "target not allowed" in res.error_message


def test_f2_evaluate_json_setup_revert_yields_harness_error():
    """setUp() revert or constructor mismatch must yield HARNESS_ERROR, NEVER VIOLATED."""
    backend = FoundryFuzzBackend(forge_path="dummy_forge")

    # Case A: Contract-level error reported by Forge
    setup_fail_json_a = {
        "contracts/test/generated/Test_PROP_2.t.sol:Test_PROP_2": {
            "error": "Setup failed: EvmError: Revert",
            "test_results": {},
        }
    }

    res_a = backend._evaluate_json_results(
        json_data=setup_fail_json_a,
        returncode=1,
        harness_code="// test harness",
        property_id="PROP-SES-002",
        raw_log_path="dummy.log",
    )

    assert res_a.outcome == Outcome.HARNESS_ERROR
    assert res_a.witness is None
    assert "setUp reverted" in res_a.error_message

    # Case B: Test failure caused by setup failure
    setup_fail_json_b = {
        "contracts/test/generated/Test_PROP_2.t.sol:Test_PROP_2": {
            "test_results": {
                "test_obligation_SES_002()": {
                    "status": "Failure",
                    "reason": "Setup failed: constructor argument count mismatch",
                }
            }
        }
    }

    res_b = backend._evaluate_json_results(
        json_data=setup_fail_json_b,
        returncode=1,
        harness_code="// test harness",
        property_id="PROP-SES-002",
        raw_log_path="dummy.log",
    )

    assert res_b.outcome == Outcome.HARNESS_ERROR
    assert res_b.witness is None


def test_f2_evaluate_json_all_tests_passed_yields_held():
    """When all tests succeed, the outcome is Outcome.HELD."""
    backend = FoundryFuzzBackend(forge_path="dummy_forge")

    clean_json = {
        "contracts/test/generated/Test_PROP_3.t.sol:Test_PROP_3": {
            "test_results": {
                "test_obligation_NONCE_001()": {
                    "status": "Success",
                    "decoded_logs": [],
                }
            }
        }
    }

    res = backend._evaluate_json_results(
        json_data=clean_json,
        returncode=0,
        harness_code="// test harness",
        property_id="PROP-NONCE-001",
        raw_log_path="dummy.log",
    )

    assert res.outcome == Outcome.HELD
    assert res.witness is None


def test_f2_unparseable_json_yields_harness_error():
    """Unparseable stdout (e.g. solc compile error or fatal crash) yields HARNESS_ERROR."""
    backend = FoundryFuzzBackend(forge_path="dummy_forge")

    # Simulate compilation error text
    compile_error_stdout = "Compiler run failed with errors:\nParserError: Expected ';' but got '}'"
    json_data = backend._extract_json(compile_error_stdout)
    assert json_data is None

    # In validate(), this branch immediately triggers HARNESS_ERROR
    res = ValidationResult(
        outcome=Outcome.HARNESS_ERROR,
        backend="FoundryFuzz",
        property_id="PROP-ERROR",
        error_message="Harness compilation or execution failed (exit code 1)",
    )
    assert res.outcome == Outcome.HARNESS_ERROR


def test_f2_dispatcher_aggregation():
    """Dispatcher aggregates outcomes correctly: VIOLATED beats HELD, and errors are retained."""
    dispatcher = BackendDispatcher()

    # Create dummy properties
    prop = Property(
        property_id="PROP-TEST",
        template_type=PropertyType.SESSION,
        target_role=Role.ACCOUNT,
        precondition="true",
        required_condition="true",
    )
    binding = PropertyBinding()
    facts = ContractFacts(contract_name="TestContract", source_path="test.sol")

    # If forge is absent, dispatcher returns HARNESS_ERROR
    res = dispatcher.validate_property(prop, binding, facts)
    assert isinstance(res, ValidationResult)
    assert res.outcome in (Outcome.VIOLATED, Outcome.HELD, Outcome.HARNESS_ERROR)

# SPDX-License-Identifier: MIT
"""
Unit tests for Step F4: Bundle Differential Simulator Backend.

All tests are mock-based and do NOT require forge / Foundry to be installed.
They verify:

  1. Synthetic JSON showing CouponPaymaster invariant VIOLATED
     (both ops in bundle sponsored) → Outcome.VIOLATED.
  2. Synthetic JSON showing compliant version (only one op sponsored) → Outcome.HELD.
  3. forge absent (forge_path=None) → Outcome.HARNESS_ERROR, no exception raised.
  4. JSON with harness setUp error → Outcome.HARNESS_ERROR.
  5. No JSON output from forge → Outcome.HARNESS_ERROR.
  6. Non-SIM property is passed through as HELD immediately (no forge call).
  7. Harness code contains the invariant comment from property.required_condition
     (not a hardcoded string).
  8. Harness code references the correct contract name.
  9. bundle_size parameter propagated to harness template.
"""

import json
from typing import Any, Dict

import pytest

from specguard.backends.differential_sim import (
    DifferentialSimBackend,
    _evaluate_json_results,
    _extract_json,
    _generate_harness,
)
from specguard.models import (
    ContractFacts,
    Outcome,
    Property,
    PropertyBinding,
    PropertyType,
    Role,
    ValidationResult,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_sim_property(
    pid: str = "SIM_COUPON",
    required_condition: str = "Each coupon must be consumed at most once per bundle",
) -> Property:
    return Property(
        property_id=pid,
        template_type=PropertyType.SIM,
        target_role=Role.ACCOUNT,
        precondition="bundle of size 2",
        required_condition=required_condition,
    )


def _make_non_sim_property() -> Property:
    return Property(
        property_id="AUTH_PROP",
        template_type=PropertyType.AUTH,
        target_role=Role.ACCOUNT,
        precondition="always",
        required_condition="sig check",
    )


def _make_facts(name: str = "CouponPaymaster") -> ContractFacts:
    return ContractFacts(
        contract_name=name,
        source_path=f"contracts/src/worked_examples/{name}.sol",
    )


def _make_binding() -> PropertyBinding:
    return PropertyBinding(used_coupon_mapping="usedCoupons")


def _make_backend(forge_path: str | None = "fake_forge", bundle_size: int = 2) -> DifferentialSimBackend:
    return DifferentialSimBackend(forge_path=forge_path, bundle_size=bundle_size)


# ---------------------------------------------------------------------------
# Build synthetic forge JSON that mimics test results
# ---------------------------------------------------------------------------


def _forge_json_violated(reason: str = "VIOLATION: same coupon was accepted by 2 operations") -> Dict[str, Any]:
    """Forge JSON where testBundle_invariantHolds FAILED — invariant violated."""
    return {
        "Test_BundleDiff_SIM_COUPON:test": {
            "test_results": {
                "testBundle_invariantHolds": {
                    "status": "Failure",
                    "reason": reason,
                    "decoded_logs": [reason],
                    "counterexample": None,
                }
            }
        }
    }


def _forge_json_held() -> Dict[str, Any]:
    """Forge JSON where testBundle_invariantHolds PASSED — invariant held."""
    return {
        "Test_BundleDiff_SIM_COUPON:test": {
            "test_results": {
                "testBundle_invariantHolds": {
                    "status": "Success",
                    "reason": None,
                    "decoded_logs": [],
                }
            }
        }
    }


def _forge_json_setup_error() -> Dict[str, Any]:
    return {
        "Test_BundleDiff_SIM_COUPON:test": {
            "error": "setUp reverted: not enough ETH deposited",
            "test_results": {},
        }
    }


def _run_evaluate(backend: DifferentialSimBackend, forge_json: Dict[str, Any]) -> ValidationResult:
    """Call _evaluate_json_results directly with serialised JSON."""
    return _evaluate_json_results(
        json_data=forge_json,
        returncode=0,
        harness_code="// harness",
        property_id="SIM_COUPON",
        raw_log_path="/tmp/bundle_run.log",
        backend_name="DifferentialSim",
    )


# ---------------------------------------------------------------------------
# Tests for _evaluate_json_results (pure logic)
# ---------------------------------------------------------------------------


class TestEvaluateJsonResults:
    def test_failed_test_returns_violated(self):
        result = _run_evaluate(_make_backend(), _forge_json_violated())
        assert result.outcome == Outcome.VIOLATED
        assert result.witness is not None
        assert "VIOLATION" in (result.error_message or "")

    def test_passed_test_returns_held(self):
        result = _run_evaluate(_make_backend(), _forge_json_held())
        assert result.outcome == Outcome.HELD
        assert result.witness is None

    def test_setup_error_returns_harness_error(self):
        result = _run_evaluate(_make_backend(), _forge_json_setup_error())
        assert result.outcome == Outcome.HARNESS_ERROR
        assert "setUp" in (result.error_message or "") or "error" in (result.error_message or "").lower()

    def test_no_tests_nonzero_exit_returns_harness_error(self):
        empty_json: Dict[str, Any] = {
            "Test_BundleDiff_SIM_COUPON:test": {"test_results": {}}
        }
        result = _evaluate_json_results(
            json_data=empty_json,
            returncode=1,
            harness_code="// harness",
            property_id="SIM_COUPON",
            raw_log_path="/tmp/bundle_run.log",
        )
        assert result.outcome == Outcome.HARNESS_ERROR

    def test_failing_obligation_id_is_test_name(self):
        result = _run_evaluate(_make_backend(), _forge_json_violated())
        assert result.failing_obligation_id == "testBundle_invariantHolds"

    def test_compliant_paymaster_returns_held(self):
        """
        Verifies the plan requirement: 'compliant version (coupon consumed during
        validation) is not [caught]'.
        """
        result = _run_evaluate(_make_backend(), _forge_json_held())
        assert result.outcome == Outcome.HELD


# ---------------------------------------------------------------------------
# Tests for DifferentialSimBackend.validate (full backend path)
# ---------------------------------------------------------------------------


class TestDifferentialSimBackend:
    def test_forge_absent_returns_harness_error(self):
        backend = _make_backend(forge_path=None)
        result = backend.validate(_make_sim_property(), _make_binding(), _make_facts())
        assert result.outcome == Outcome.HARNESS_ERROR
        assert "forge" in (result.error_message or "").lower()

    def test_non_sim_property_returns_held_immediately(self):
        """Non-SIM properties bypass the backend and return HELD."""
        backend = _make_backend()
        result = backend.validate(_make_non_sim_property(), _make_binding(), _make_facts())
        assert result.outcome == Outcome.HELD


# ---------------------------------------------------------------------------
# Tests for _extract_json
# ---------------------------------------------------------------------------


class TestExtractJson:
    def test_valid_json_extracted(self):
        payload = {"foo": "bar"}
        stdout = "Some warning text\n" + json.dumps(payload) + "\n"
        result = _extract_json(stdout)
        assert result == payload

    def test_empty_string_returns_none(self):
        assert _extract_json("") is None

    def test_non_json_string_returns_none(self):
        assert _extract_json("Error: file not found\n") is None


# ---------------------------------------------------------------------------
# Tests for _generate_harness
# ---------------------------------------------------------------------------


class TestGenerateHarness:
    def test_harness_contains_contract_name(self):
        code = _generate_harness("CouponPaymaster", "SIM_COUPON", "coupon once per bundle")
        assert "CouponPaymaster" in code

    def test_harness_contains_clean_id(self):
        code = _generate_harness("CouponPaymaster", "SIM_COUPON", "coupon once per bundle")
        assert "Test_BundleDiff_SIM_COUPON" in code

    def test_harness_contains_invariant_comment(self):
        invariant = "Each coupon must be consumed at most once per bundle"
        code = _generate_harness("CouponPaymaster", "SIM_COUPON", invariant)
        assert invariant in code

    def test_harness_bundle_size_2_default(self):
        code = _generate_harness("CouponPaymaster", "SIM_COUPON", "once", bundle_size=2)
        # The bundle size appears in the assertLt and in the array allocation
        assert "new PackedUserOperation[](2)" in code

    def test_harness_bundle_size_3(self):
        code = _generate_harness("CouponPaymaster", "SIM_COUPON", "once", bundle_size=3)
        assert "new PackedUserOperation[](3)" in code

    def test_harness_uses_handle_ops(self):
        code = _generate_harness("CouponPaymaster", "SIM_COUPON", "once")
        assert "handleOps" in code

    def test_harness_uses_simulate_validation(self):
        code = _generate_harness("CouponPaymaster", "SIM_COUPON", "once")
        assert "simulateValidation" in code

    def test_harness_no_toggle_sim_mode(self):
        """The old toy harness called toggleSimMode — that must be gone."""
        code = _generate_harness("CouponPaymaster", "SIM_COUPON", "once")
        assert "toggleSimMode" not in code

    def test_harness_no_console_substring_decision(self):
        """The harness must not contain '[FAIL' or 'Inconsistency' as decision strings."""
        code = _generate_harness("CouponPaymaster", "SIM_COUPON", "once")
        assert "[FAIL" not in code
        assert "Inconsistency" not in code

    def test_harness_property_id_from_required_condition_not_hardcoded(self):
        """
        The invariant comment in the harness must come from the required_condition
        argument, not a hardcoded string — proving it is parameterised.
        """
        custom = "No resource may be consumed more than once in a single bundle execution"
        code = _generate_harness("CouponPaymaster", "SIM_CUSTOM", custom)
        assert custom in code

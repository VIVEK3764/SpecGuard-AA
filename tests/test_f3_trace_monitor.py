# SPDX-License-Identifier: MIT
"""
Unit tests for Step F3: EVM Trace Monitor Backend.

All tests are mock-based and do NOT require forge / Foundry to be installed.
They verify:

  1. Synthetic JSON trace with TIMESTAMP at depth 1 → VIOLATED, rule OP-011.
  2. Synthetic JSON trace with BALANCE on op.sender itself → HELD for STO-010
     (BALANCE is flagged under OP-080, not STO-010, because sender self-access
     is allowed by STO-010; we verify OP-080 is the reported rule).
  3. TIMESTAMP reached through a two-level internal call (depth 2) → VIOLATED,
     OP-011 (proves we don't stop at depth 1).
  4. Variable named ``_balances`` in source but NO BALANCE opcode in trace →
     HELD (source regex false-positive suppressed).
  5. forge absent (forge_path=None) → HARNESS_ERROR without raising.
  6. JSON with harness setUp error → HARNESS_ERROR.
  7. GAS immediately before CALL → HELD for OP-012.
  8. GAS NOT immediately before CALL → VIOLATED, OP-012.
"""

import json
from unittest.mock import MagicMock, patch

import pytest

from specguard.backends.trace_monitor import (
    TraceEvent,
    TraceMonitorBackend,
    evaluate_rules,
    _parse_forge_trace_json,
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

SENDER = "0xsender0000000000000000000000000000000001"
ENTRY_POINT = "0xentrypoint000000000000000000000000000001"
OTHER_CONTRACT = "0xother00000000000000000000000000000000001"


def _make_property(pid: str = "SCOPE_TEST") -> Property:
    return Property(
        property_id=pid,
        template_type=PropertyType.SCOPE,
        target_role=Role.ACCOUNT,
        precondition="always",
        required_condition="no forbidden opcodes",
    )


def _make_facts(name: str = "TestAccount") -> ContractFacts:
    return ContractFacts(
        contract_name=name,
        source_path=f"contracts/src/worked_examples/{name}.sol",
    )


def _make_binding() -> PropertyBinding:
    return PropertyBinding()


def _make_backend(forge_path: str | None = "fake_forge") -> TraceMonitorBackend:
    """Backend with a non-None forge_path so it doesn't short-circuit."""
    b = TraceMonitorBackend(
        forge_path=forge_path,
        sender_address=SENDER,
        entry_point_address=ENTRY_POINT,
    )
    return b


def _build_forge_json(steps: list[dict], address: str = SENDER) -> dict:
    """
    Build a minimal forge --json -vvvv response for a single test with the
    given steps in the trace arena.
    """
    return {
        "FakeContract:test": {
            "test_results": {
                "testTrace_validationScope": {
                    "status": "Success",
                    "decoded_logs": [],
                    "traces": [
                        {
                            "arena": [
                                {
                                    "address": address,
                                    "depth": 0,
                                    "steps": steps,
                                }
                            ]
                        }
                    ],
                }
            }
        }
    }


def _run_with_json(backend: TraceMonitorBackend, forge_json: dict) -> ValidationResult:
    """
    Call backend._evaluate with the given dict serialised to JSON (simulates
    what forge would return on stdout).
    """
    stdout = json.dumps(forge_json)
    return backend._evaluate(
        stdout=stdout,
        returncode=0,
        harness_code="// harness",
        property_id="SCOPE_TEST",
        raw_log_path="/tmp/trace_run.log",
    )


# ---------------------------------------------------------------------------
# evaluate_rules unit tests (pure logic, no I/O)
# ---------------------------------------------------------------------------


class TestEvaluateRules:
    """Pure unit tests for the ERC-7562 rule evaluator."""

    def test_timestamp_at_depth_1_violates_OP011(self):
        trace = [TraceEvent(opcode="TIMESTAMP", depth=1, address=SENDER)]
        violations = evaluate_rules(trace, sender=SENDER, entry_point=ENTRY_POINT)
        rule_ids = [v.rule_id for v in violations]
        assert "OP-011" in rule_ids, f"Expected OP-011, got {rule_ids}"

    def test_timestamp_at_depth_2_violates_OP011(self):
        """Two-level internal call: TIMESTAMP still triggers OP-011."""
        trace = [TraceEvent(opcode="TIMESTAMP", depth=2, address=OTHER_CONTRACT)]
        violations = evaluate_rules(trace, sender=SENDER, entry_point=ENTRY_POINT)
        rule_ids = [v.rule_id for v in violations]
        assert "OP-011" in rule_ids

    def test_balance_on_sender_flags_OP080(self):
        """BALANCE used by sender is OP-080 (staked-entity check), NOT STO-010."""
        trace = [TraceEvent(opcode="BALANCE", depth=1, address=SENDER)]
        violations = evaluate_rules(trace, sender=SENDER, entry_point=ENTRY_POINT)
        rule_ids = [v.rule_id for v in violations]
        # OP-080 must be flagged
        assert "OP-080" in rule_ids
        # STO-010 must NOT be flagged (sender's own BALANCE access is STO-permitted)
        assert "STO-010" not in rule_ids

    def test_sload_in_external_contract_violates_STO010(self):
        trace = [TraceEvent(opcode="SLOAD", depth=1, address=OTHER_CONTRACT, storage_key="0xabc")]
        violations = evaluate_rules(trace, sender=SENDER, entry_point=ENTRY_POINT)
        rule_ids = [v.rule_id for v in violations]
        assert "STO-010" in rule_ids

    def test_sload_in_sender_is_clean(self):
        """Sender reading its own storage must NOT be flagged."""
        trace = [TraceEvent(opcode="SLOAD", depth=1, address=SENDER, storage_key="0x0")]
        violations = evaluate_rules(trace, sender=SENDER, entry_point=ENTRY_POINT)
        rule_ids = [v.rule_id for v in violations]
        assert "STO-010" not in rule_ids
        assert "STO-021" not in rule_ids

    def test_sload_in_entry_point_is_clean(self):
        """EntryPoint reading storage during validation is not a STO violation."""
        trace = [TraceEvent(opcode="SLOAD", depth=1, address=ENTRY_POINT, storage_key="0x1")]
        violations = evaluate_rules(trace, sender=SENDER, entry_point=ENTRY_POINT)
        rule_ids = [v.rule_id for v in violations]
        assert "STO-010" not in rule_ids

    def test_gas_immediately_before_call_is_clean(self):
        """GAS immediately before CALL must NOT trigger OP-012."""
        trace = [
            TraceEvent(opcode="GAS", depth=1, address=SENDER, index=0),
            TraceEvent(opcode="CALL", depth=1, address=SENDER, index=1),
        ]
        violations = evaluate_rules(trace, sender=SENDER, entry_point=ENTRY_POINT)
        rule_ids = [v.rule_id for v in violations]
        assert "OP-012" not in rule_ids

    def test_bare_gas_not_before_call_violates_OP012(self):
        """GAS NOT followed by a *CALL opcode must trigger OP-012."""
        trace = [
            TraceEvent(opcode="GAS", depth=1, address=SENDER, index=0),
            TraceEvent(opcode="POP", depth=1, address=SENDER, index=1),
        ]
        violations = evaluate_rules(trace, sender=SENDER, entry_point=ENTRY_POINT)
        rule_ids = [v.rule_id for v in violations]
        assert "OP-012" in rule_ids

    def test_call_with_value_violates_OP061(self):
        trace = [
            TraceEvent(opcode="CALL", depth=1, address=SENDER, value=1_000, target=OTHER_CONTRACT)
        ]
        violations = evaluate_rules(trace, sender=SENDER, entry_point=ENTRY_POINT)
        rule_ids = [v.rule_id for v in violations]
        assert "OP-061" in rule_ids

    def test_call_with_value_to_entry_point_is_clean(self):
        """CALL with value to EntryPoint is the exception carved by OP-061."""
        trace = [
            TraceEvent(opcode="CALL", depth=1, address=SENDER, value=1_000, target=ENTRY_POINT)
        ]
        violations = evaluate_rules(trace, sender=SENDER, entry_point=ENTRY_POINT)
        rule_ids = [v.rule_id for v in violations]
        assert "OP-061" not in rule_ids

    def test_selfdestruct_violates_OP013(self):
        trace = [TraceEvent(opcode="SELFDESTRUCT", depth=1, address=SENDER)]
        violations = evaluate_rules(trace, sender=SENDER, entry_point=ENTRY_POINT)
        rule_ids = [v.rule_id for v in violations]
        assert "OP-013" in rule_ids

    def test_clean_trace_has_no_violations(self):
        """A trace with only ADD, MSTORE, RETURN must produce zero violations."""
        trace = [
            TraceEvent(opcode="ADD", depth=1, address=SENDER),
            TraceEvent(opcode="MSTORE", depth=1, address=SENDER),
            TraceEvent(opcode="RETURN", depth=1, address=SENDER),
        ]
        violations = evaluate_rules(trace, sender=SENDER, entry_point=ENTRY_POINT)
        assert violations == []

    def test_no_false_positive_from_variable_name(self):
        """
        A contract with a state variable named _balances must NOT trigger BALANCE
        violation — only the opcode in the trace matters, not source text.
        """
        # Trace has no BALANCE opcode
        trace = [
            TraceEvent(opcode="SLOAD", depth=1, address=SENDER, storage_key="0x0"),
            TraceEvent(opcode="RETURN", depth=1, address=SENDER),
        ]
        violations = evaluate_rules(trace, sender=SENDER, entry_point=ENTRY_POINT)
        rule_ids = [v.rule_id for v in violations]
        assert "OP-080" not in rule_ids, (
            "_balances variable name must not cause false-positive BALANCE opcode flag"
        )


# ---------------------------------------------------------------------------
# Integration-style tests through the full backend._evaluate path
# ---------------------------------------------------------------------------


class TestTraceMonitorBackendEvaluate:
    """Tests for the full backend evaluate path with mocked forge output."""

    def test_timestamp_in_trace_returns_violated(self):
        backend = _make_backend()
        forge_json = _build_forge_json(
            steps=[{"op": "TIMESTAMP", "depth": 1}],
            address=SENDER,
        )
        result = _run_with_json(backend, forge_json)
        assert result.outcome == Outcome.VIOLATED
        assert result.failing_obligation_id == "OP-011"
        assert result.witness is not None
        assert "OP-011" in result.witness.user_op_json["violated_rules"]

    def test_timestamp_at_depth_2_returns_violated(self):
        """Verifies the two-level internal call case required by the plan."""
        backend = _make_backend()
        forge_json = _build_forge_json(
            steps=[{"op": "TIMESTAMP", "depth": 2}],
            address=OTHER_CONTRACT,
        )
        result = _run_with_json(backend, forge_json)
        assert result.outcome == Outcome.VIOLATED
        assert result.failing_obligation_id == "OP-011"

    def test_balances_variable_name_no_opcode_returns_held(self):
        """
        Contract with _balances variable name: trace has only SLOAD on sender
        and RETURN — must return HELD (no source-text matching).
        """
        backend = _make_backend()
        forge_json = _build_forge_json(
            steps=[
                {"op": "SLOAD", "depth": 1, "storage_key": "0x0"},
                {"op": "RETURN", "depth": 1},
            ],
            address=SENDER,
        )
        result = _run_with_json(backend, forge_json)
        assert result.outcome == Outcome.HELD

    def test_forge_absent_returns_harness_error(self):
        """forge_path=None must return HARNESS_ERROR, not raise."""
        backend = _make_backend(forge_path=None)
        prop = _make_property()
        facts = _make_facts()
        binding = _make_binding()
        result = backend.validate(prop, binding, facts)
        assert result.outcome == Outcome.HARNESS_ERROR
        assert "forge" in (result.error_message or "").lower()

    def test_harness_setup_error_returns_harness_error(self):
        """JSON with a contract-level error field → HARNESS_ERROR."""
        backend = _make_backend()
        forge_json = {
            "FakeContract:test": {
                "error": "setUp reverted: not enough ETH",
                "test_results": {},
            }
        }
        result = _run_with_json(backend, forge_json)
        assert result.outcome == Outcome.HARNESS_ERROR
        assert "setUp" in (result.error_message or "") or "error" in (result.error_message or "").lower()

    def test_no_json_output_returns_harness_error(self):
        backend = _make_backend()
        result = backend._evaluate(
            stdout="Compiler Error: missing file\n",
            returncode=1,
            harness_code="// harness",
            property_id="SCOPE_TEST",
            raw_log_path="/tmp/trace_run.log",
        )
        assert result.outcome == Outcome.HARNESS_ERROR

    def test_non_scope_property_returns_held_immediately(self):
        """Non-SCOPE properties must be passed through as HELD."""
        backend = _make_backend()
        prop = Property(
            property_id="AUTH_TEST",
            template_type=PropertyType.AUTH,
            target_role=Role.ACCOUNT,
            precondition="always",
            required_condition="sig check",
        )
        result = backend.validate(prop, _make_binding(), _make_facts())
        assert result.outcome == Outcome.HELD


# ---------------------------------------------------------------------------
# _parse_forge_trace_json unit tests
# ---------------------------------------------------------------------------


class TestParseForgeTraceJson:
    def test_parses_steps_from_arena(self):
        forge_json = _build_forge_json(
            steps=[
                {"op": "PUSH1", "depth": 0},
                {"op": "TIMESTAMP", "depth": 1},
            ],
            address=SENDER,
        )
        events = _parse_forge_trace_json(forge_json)
        ops = [e.opcode for e in events]
        assert "PUSH1" in ops
        assert "TIMESTAMP" in ops

    def test_address_propagated_from_arena_node(self):
        forge_json = _build_forge_json(
            steps=[{"op": "SLOAD", "depth": 1}],
            address=OTHER_CONTRACT,
        )
        events = _parse_forge_trace_json(forge_json)
        assert all(e.address == OTHER_CONTRACT.lower() for e in events)

    def test_empty_arena_returns_empty_list(self):
        forge_json = {
            "contract:test": {
                "test_results": {
                    "testFn": {
                        "status": "Success",
                        "traces": [{"arena": []}],
                    }
                }
            }
        }
        events = _parse_forge_trace_json(forge_json)
        assert events == []

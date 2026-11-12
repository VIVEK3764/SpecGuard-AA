# SPDX-License-Identifier: MIT
"""
Tests for SpecGuard-AA 5.3 (Trace Monitor) and 5.4 (Differential Simulator).
"""

import os
from specguard.extractor import extract_facts
from specguard.backends.trace_monitor import TraceMonitorBackend
from specguard.backends.differential_sim import DifferentialSimBackend
from specguard.models import Property, PropertyBinding, PropertyType, Role, Outcome


SCOPE_VIOLATING_PATH = os.path.join(
    "contracts", "src", "worked_examples", "ScopeAccountViolating.sol"
)
SCOPE_COMPLIANT_PATH = os.path.join(
    "contracts", "src", "worked_examples", "ScopeAccountCompliant.sol"
)
SIM_VIOLATING_PATH = os.path.join(
    "contracts", "src", "worked_examples", "SimAccountViolating.sol"
)
SIM_COMPLIANT_PATH = os.path.join(
    "contracts", "src", "worked_examples", "SimAccountCompliant.sol"
)


def test_trace_monitor_backend_positive_fixture():
    """5.3 Trace Monitor: ScopeAccountViolating.sol flags forbidden opcode read."""
    facts = extract_facts(SCOPE_VIOLATING_PATH)

    prop = Property(
        property_id="PROP-SCOPE-001",
        template_type=PropertyType.SCOPE,
        target_role=Role.ACCOUNT,
        bindings=PropertyBinding(validator_function="validateUserOp"),
        precondition="simulatingValidation(op)",
        required_condition="NOT forbiddenOpcodeExecuted(tr)",
        source_chunk_ids=["ERC7562-SCOPE-001"],
    )
    binding = PropertyBinding(validator_function="validateUserOp")

    backend = TraceMonitorBackend()
    res = backend.validate(prop, binding, facts)

    assert res.outcome == Outcome.VIOLATED, "Trace monitor MUST flag forbidden timestamp/balance opcode read"
    assert res.witness is not None
    assert res.witness.backend == "TraceMonitor"


def test_trace_monitor_backend_negative_fixture():
    """5.3 Trace Monitor: ScopeAccountCompliant.sol returns Outcome.HELD."""
    facts = extract_facts(SCOPE_COMPLIANT_PATH)

    prop = Property(
        property_id="PROP-SCOPE-002",
        template_type=PropertyType.SCOPE,
        target_role=Role.ACCOUNT,
        bindings=PropertyBinding(validator_function="validateUserOp"),
        precondition="simulatingValidation(op)",
        required_condition="NOT forbiddenOpcodeExecuted(tr)",
        source_chunk_ids=["ERC7562-SCOPE-001"],
    )
    binding = PropertyBinding(validator_function="validateUserOp")

    backend = TraceMonitorBackend()
    res = backend.validate(prop, binding, facts)

    assert res.outcome == Outcome.HELD, "Trace monitor MUST return Outcome.HELD for compliant scope validation"
    assert res.witness is None


def test_differential_sim_backend_positive_fixture():
    """5.4 Differential Sim: SimAccountViolating.sol flags simulation/execution diff."""
    facts = extract_facts(SIM_VIOLATING_PATH)

    prop = Property(
        property_id="PROP-SIM-001",
        template_type=PropertyType.SIM,
        target_role=Role.ACCOUNT,
        bindings=PropertyBinding(validator_function="validateUserOp"),
        precondition="simulatingValidation(op)",
        required_condition="simulationEqualsExecution(op)",
        source_chunk_ids=["ERC7562-SCOPE-003"],
    )
    binding = PropertyBinding(validator_function="validateUserOp")

    backend = DifferentialSimBackend()
    res = backend.validate(prop, binding, facts)

    assert res.outcome == Outcome.VIOLATED, "Differential simulator MUST flag simulation inconsistency"
    assert res.witness is not None
    assert res.witness.backend == "DifferentialSim"


def test_differential_sim_backend_negative_fixture():
    """5.4 Differential Sim: SimAccountCompliant.sol returns Outcome.HELD."""
    facts = extract_facts(SIM_COMPLIANT_PATH)

    prop = Property(
        property_id="PROP-SIM-002",
        template_type=PropertyType.SIM,
        target_role=Role.ACCOUNT,
        bindings=PropertyBinding(validator_function="validateUserOp"),
        precondition="simulatingValidation(op)",
        required_condition="simulationEqualsExecution(op)",
        source_chunk_ids=["ERC7562-SCOPE-003"],
    )
    binding = PropertyBinding(validator_function="validateUserOp")

    backend = DifferentialSimBackend()
    res = backend.validate(prop, binding, facts)

    assert res.outcome == Outcome.HELD, "Differential simulator MUST return Outcome.HELD when paths agree"
    assert res.witness is None

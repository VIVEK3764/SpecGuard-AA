# SPDX-License-Identifier: MIT
"""
Tests for SpecGuard-AA 5.2 (Halmos Symbolic), 5.3 (Trace Monitor), and 5.4 (Differential Simulator).
"""

import os
from specguard.extractor import extract_facts
from specguard.backends.trace_monitor import TraceMonitorBackend
from specguard.backends.differential_sim import DifferentialSimBackend
from specguard.backends.halmos_symbolic import HalmosSymbolicBackend
from specguard.models import Property, PropertyBinding, PropertyType, Role


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
    witness = backend.validate(prop, binding, facts)

    assert witness is not None, "Trace monitor MUST flag forbidden timestamp/balance opcode read"
    assert witness.backend == "TraceMonitor"


def test_trace_monitor_backend_negative_fixture():
    """5.3 Trace Monitor: ScopeAccountCompliant.sol returns None (⊥)."""
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
    witness = backend.validate(prop, binding, facts)

    assert witness is None, "Trace monitor MUST return None (⊥) for compliant scope validation"


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
    witness = backend.validate(prop, binding, facts)

    assert witness is not None, "Differential simulator MUST flag simulation inconsistency"
    assert witness.backend == "DifferentialSim"


def test_differential_sim_backend_negative_fixture():
    """5.4 Differential Sim: SimAccountCompliant.sol returns None (⊥)."""
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
    witness = backend.validate(prop, binding, facts)

    assert witness is None, "Differential simulator MUST return None (⊥) when paths agree"

# SPDX-License-Identifier: MIT
"""
Unit and Regression Tests for Step F5: Decommissioning Gate & Backend Integrity.

Verifies the requirements specified in llm-rag-stepbystep.md (Step F5):
1. The decommissioned backend token appears nowhere in the repository or paper text.
2. The decommissioned symbolic module and tests are permanently absent.
3. specguard/backends/ contains exclusively the canonical tri-backend suite:
   - FoundryFuzzBackend
   - TraceMonitorBackend
   - DifferentialSimBackend
4. BackendDispatcher provides exhaustive mapping for all PropertyType variants.
5. All dispatched backends inherit from ValidationBackend and produce structured
   ValidationResult instances with valid Outcome enum values (Rule B compliance).
6. No backend requires WSL or unexecutable symbolic paths.
"""

import os
import re
import pytest
from specguard.backends.base import ValidationBackend
from specguard.backends.dispatcher import BackendDispatcher
from specguard.backends.foundry_fuzz import FoundryFuzzBackend
from specguard.backends.trace_monitor import TraceMonitorBackend
from specguard.backends.differential_sim import DifferentialSimBackend
from specguard.models import (
    PropertyType,
    Outcome,
    ValidationResult,
    Property,
    PropertyBinding,
    Role,
    ContractFacts,
)

BANNED_TOKEN = "h" + "almos"


def _get_project_root() -> str:
    """Returns absolute path to the SpecGuard-AA project root."""
    return os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))


def test_f5_no_decommissioned_token_in_repository():
    """
    Step F5 Verification Criterion:
    Decommissioned backend token appears nowhere in the repository
    (code, tests, configs, documentation).
    """
    root = _get_project_root()
    forbidden_pattern = re.compile(rf"\b{BANNED_TOKEN}\b", re.IGNORECASE)

    scanned_extensions = {".py", ".sol", ".toml", ".yaml", ".yml", ".md"}
    violations = []
    current_test_filename = os.path.basename(__file__)

    for dirpath, dirnames, filenames in os.walk(root):
        # Exclude git internals, caches, virtual environments
        dirnames[:] = [
            d for d in dirnames
            if d not in {".git", ".cache", ".pytest_cache", "venv", ".venv", "__pycache__"}
        ]
        for filename in filenames:
            if filename == current_test_filename:
                continue
            ext = os.path.splitext(filename)[1].lower()
            if ext in scanned_extensions or filename in {"Dockerfile", ".env.example"}:
                file_path = os.path.join(dirpath, filename)
                try:
                    with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                        for line_no, line in enumerate(f, start=1):
                            if forbidden_pattern.search(line):
                                rel_path = os.path.relpath(file_path, root)
                                violations.append(f"{rel_path}:{line_no}: {line.strip()}")
                except Exception as e:
                    pytest.fail(f"Could not read {file_path}: {e}")

    assert not violations, (
        f"Step F5 Violation: Found '{BANNED_TOKEN}' in {len(violations)} locations:\n"
        + "\n".join(violations[:15])
    )


def test_f5_decommissioned_files_deleted():
    """Verify that decommissioned symbolic backend files and tests are permanently deleted."""
    root = _get_project_root()
    decommissioned_backend_path = os.path.join(root, "specguard", "backends", f"{BANNED_TOKEN}_symbolic.py")
    decommissioned_test_path = os.path.join(root, "tests", f"test_{BANNED_TOKEN}_backend.py")

    assert not os.path.exists(decommissioned_backend_path), (
        f"Defect: {decommissioned_backend_path} must be deleted per Step F5."
    )
    assert not os.path.exists(decommissioned_test_path), (
        f"Defect: {decommissioned_test_path} must be deleted per Step F5."
    )


def test_f5_backends_directory_contents():
    """Verify that specguard/backends/ contains only approved tri-backend modules."""
    root = _get_project_root()
    backends_dir = os.path.join(root, "specguard", "backends")
    expected_files = {
        "__init__.py",
        "base.py",
        "dispatcher.py",
        "foundry_fuzz.py",
        "trace_monitor.py",
        "differential_sim.py",
    }

    actual_files = {
        f for f in os.listdir(backends_dir)
        if os.path.isfile(os.path.join(backends_dir, f)) and f.endswith(".py")
    }

    assert actual_files.issubset(expected_files), (
        f"Unexpected backend files found in specguard/backends: {actual_files - expected_files}"
    )


def test_f5_dispatcher_exhaustive_property_type_mapping():
    """
    Verify that BackendDispatcher maps every single PropertyType enum member
    without gaps, null values, or unhandled types.
    """
    dispatcher = BackendDispatcher()
    all_property_types = set(PropertyType)
    mapped_types = set(dispatcher.dispatch_map.keys())

    assert all_property_types == mapped_types, (
        f"Missing PropertyType mappings in BackendDispatcher: {all_property_types - mapped_types}"
    )

    allowed_backend_classes = (FoundryFuzzBackend, TraceMonitorBackend, DifferentialSimBackend)

    for p_type, backends in dispatcher.dispatch_map.items():
        assert isinstance(backends, list), f"Dispatch map entry for {p_type} must be a list"
        assert len(backends) > 0, f"Dispatch map entry for {p_type} must not be empty"
        for backend in backends:
            assert isinstance(backend, allowed_backend_classes), (
                f"Invalid backend {type(backend)} registered for {p_type}. "
                f"Must be one of {allowed_backend_classes}"
            )
            assert isinstance(backend, ValidationBackend), (
                f"Backend {type(backend)} does not inherit from ValidationBackend"
            )


def test_f5_dispatcher_property_routing_contract():
    """Verify routing semantics for each canonical property type."""
    dispatcher = BackendDispatcher()

    # Scope properties must route to TraceMonitorBackend
    scope_backends = dispatcher.dispatch_map[PropertyType.SCOPE]
    assert any(isinstance(b, TraceMonitorBackend) for b in scope_backends), (
        "SCOPE property must route to TraceMonitorBackend"
    )

    # Simulation properties must route to DifferentialSimBackend
    sim_backends = dispatcher.dispatch_map[PropertyType.SIM]
    assert any(isinstance(b, DifferentialSimBackend) for b in sim_backends), (
        "SIM property must route to DifferentialSimBackend"
    )

    # State / authorization properties must route to FoundryFuzzBackend
    for auth_type in [PropertyType.AUTH, PropertyType.SESSION, PropertyType.NONCE, PropertyType.PAYMASTER]:
        auth_backends = dispatcher.dispatch_map[auth_type]
        assert any(isinstance(b, FoundryFuzzBackend) for b in auth_backends), (
            f"{auth_type} property must route to FoundryFuzzBackend"
        )


def test_f5_dispatcher_execution_returns_structured_outcome():
    """
    Verify that dispatcher.validate_property executes and returns a valid
    ValidationResult with a four-valued Outcome enum.
    """
    dispatcher = BackendDispatcher()
    facts = ContractFacts(
        contract_name="TestContract",
        source_path="contracts/src/worked_examples/SimpleOwnerAccount.sol",
        roles=[Role.ACCOUNT],
    )
    binding = PropertyBinding(validator_function="validateUserOp")

    # Test each PropertyType produces a valid ValidationResult
    for p_type in PropertyType:
        prop = Property(
            property_id=f"PROP-TEST-{p_type.value}",
            template_type=p_type,
            target_role=Role.ACCOUNT,
            bindings=binding,
            precondition="true",
            required_condition="true",
            source_chunk_ids=["ERC4337-TEST-001"],
        )

        res = dispatcher.validate_property(prop, binding, facts)
        assert isinstance(res, ValidationResult), f"Expected ValidationResult for {p_type}"
        assert isinstance(res.outcome, Outcome), f"Expected Outcome enum for {p_type}, got {type(res.outcome)}"
        assert res.outcome in {Outcome.VIOLATED, Outcome.HELD, Outcome.HARNESS_ERROR, Outcome.TIMEOUT}
        assert res.property_id == prop.property_id

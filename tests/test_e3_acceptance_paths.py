# SPDX-License-Identifier: MIT
"""
Dedicated Unit Tests for Step E3: Acceptance Path Enumeration & Protocol Version Inference.

Verifies:
1. infer_protocol_version identifies v0.6 vs v0.7 based on struct types and library hints.
2. extract_acceptance_paths distinguishes multi-branch acceptance paths (owner vs session path).
3. Session path correctly records is_local_digest = True and distinct digest expression.
4. Owner path correctly records is_local_digest = False and userOpHash digest expression.
5. extract_admin_setups identifies functions writing state variables with caller guards.
"""

import pytest
from specguard.models import ProtocolVersion, AcceptancePath, AdminFunctionSetup
from specguard.facts.acceptance_paths import (
    infer_protocol_version,
    extract_acceptance_paths,
    extract_admin_setups,
)


class MockParameter:
    def __init__(self, name: str, type_str: str):
        self.name = name
        self.type = type_str


class MockNode:
    def __init__(self, content: str, node_type="STATEMENT", state_vars_read=None):
        self.content = content
        self.type = node_type
        self.state_variables_read = state_vars_read or []
        self.sons = []

    def __str__(self):
        return self.content


class MockFunction:
    def __init__(self, name: str, params=None, nodes=None, state_vars_read=None, state_vars_written=None, modifiers=None):
        self.name = name
        self.parameters = params or []
        self.nodes = nodes or []
        self.state_variables_read = state_vars_read or []
        self.state_variables_written = state_vars_written or []
        self.modifiers = modifiers or []
        self.visibility = "external"
        self.contract_declarer = None
        self.is_implemented = True
        self.is_constructor = False
        self.entry_point = self.nodes[0] if self.nodes else None


class MockStateVariable:
    def __init__(self, name: str, type_str: str = "address"):
        self.name = name
        self.type = type_str
        self.is_constant = False
        self.is_immutable = False


class MockContract:
    def __init__(self, name: str, functions=None, state_variables=None, source_content: str = ""):
        self.name = name
        self.functions = functions or []
        self.state_variables = state_variables or []
        self.source_mapping = type("Mapping", (), {"content": source_content})()
        for f in self.functions:
            f.contract_declarer = self


def test_infer_protocol_version_v07_packed_struct():
    """PackedUserOperation in validateUserOp parameter indicates v0.7."""
    fn = MockFunction(
        "validateUserOp",
        params=[
            MockParameter("op", "PackedUserOperation"),
            MockParameter("userOpHash", "bytes32"),
            MockParameter("missingAccountFunds", "uint256"),
        ],
    )
    contract = MockContract("SimpleV07Account", functions=[fn])
    assert infer_protocol_version(contract) == ProtocolVersion.V0_7


def test_infer_protocol_version_v06_unpacked_struct():
    """Unpacked UserOperation indicates v0.6."""
    fn = MockFunction(
        "validateUserOp",
        params=[
            MockParameter("op", "UserOperation"),
            MockParameter("userOpHash", "bytes32"),
        ],
    )
    contract = MockContract("LegacyV06Account", functions=[fn])
    assert infer_protocol_version(contract) == ProtocolVersion.V0_6


def test_acceptance_paths_multi_path_session_account():
    """
    Step E3 Done-when:
    Running on a session account reports two acceptance paths with distinct digest bindings.
    """
    owner_var = MockStateVariable("owner", "address")
    session_var = MockStateVariable("sessionKey", "mapping(address => bool)")

    # Simulate validateUserOp CFG with owner and session branches
    n_entry = MockNode("ENTRY")
    n_owner = MockNode("if (op.signature.length == 65) return ECDSA.recover(userOpHash, sig) == owner;", state_vars_read=[owner_var])
    n_session = MockNode("bytes32 h = keccak256(abi.encode(op.sender, op.callData)); return sessionKey[k];", state_vars_read=[session_var])

    fn = MockFunction(
        "validateUserOp",
        params=[MockParameter("op", "PackedUserOperation"), MockParameter("userOpHash", "bytes32")],
        nodes=[n_entry, n_owner, n_session],
        state_vars_read=[owner_var, session_var],
    )

    contract = MockContract("SessionAccount", functions=[fn], state_variables=[owner_var, session_var])
    paths = extract_acceptance_paths(contract)

    assert len(paths) == 2, f"Expected 2 acceptance paths, got {len(paths)}"
    path_ids = [p.path_id for p in paths]
    assert "path_0_owner" in path_ids
    assert "path_1_session" in path_ids

    owner_path = next(p for p in paths if "owner" in p.path_id)
    session_path = next(p for p in paths if "session" in p.path_id)

    # Owner path uses userOpHash and is NOT local digest
    assert owner_path.is_local_digest is False
    assert owner_path.digest_expression == "userOpHash"
    assert "owner" in owner_path.state_vars_read

    # Session path uses local digest and is local digest
    assert session_path.is_local_digest is True
    assert "keccak256" in session_path.digest_expression
    assert "sessionKey" in session_path.state_vars_read


def test_acceptance_paths_single_path_simple_account():
    """
    Step E3 Done-when:
    Running on EthInfinitism_SimpleAccount reports ONE acceptance path.
    """
    owner_var = MockStateVariable("owner", "address")
    n1 = MockNode("return _validateSignature(op, userOpHash);", state_vars_read=[owner_var])

    fn = MockFunction(
        "validateUserOp",
        params=[MockParameter("op", "PackedUserOperation"), MockParameter("userOpHash", "bytes32")],
        nodes=[n1],
        state_vars_read=[owner_var],
    )

    contract = MockContract("SimpleAccount", functions=[fn], state_variables=[owner_var])
    paths = extract_acceptance_paths(contract)

    assert len(paths) == 1
    assert paths[0].is_local_digest is False


def test_extract_admin_setups():
    """Step F1 requirement: Discovers administrative functions that write state variables."""
    key_var = MockStateVariable("sessionKey", "mapping(address => bool)")
    fn_set = MockFunction(
        "setSessionKey",
        params=[MockParameter("key", "address"), MockParameter("target", "address")],
        state_vars_written=[key_var],
        modifiers=[type("Mod", (), {"name": "onlyOwner"})()],
    )

    contract = MockContract("SessionAccount", functions=[fn_set], state_variables=[key_var])
    setups = extract_admin_setups(contract)

    assert len(setups) == 1
    assert setups[0].function_name == "setSessionKey"
    assert setups[0].target_state_var == "sessionKey"
    assert setups[0].caller_guard == "onlyOwner"

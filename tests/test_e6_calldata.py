# SPDX-License-Identifier: MIT
"""
Dedicated Unit Tests for Step E6: Execution Interface Detection & callData Decoding.

Verifies:
1. Detects classic execute(address,uint256,bytes) -> ExecutionInterface.CLASSIC.
2. Detects executeBatch(...) -> ExecutionInterface.BATCH.
3. Detects ERC-7579 execute(bytes32 mode, bytes executionCalldata) -> ExecutionInterface.ERC7579.
4. Returns UNRESOLVED for plugin dispatch or unfamiliar execution encodings.
5. Emits binding adequacy check assertion comparing bound target to runtime called address.
"""

import pytest
from specguard.models import ContractFacts, FunctionFact, Role, ExecutionInterface
from specguard.binding.calldata import CallDataDecoder


def _make_facts_with_function(fn_name: str, params: list) -> ContractFacts:
    return ContractFacts(
        contract_name="TestAccount",
        source_path="contracts/src/TestAccount.sol",
        roles=[Role.ACCOUNT],
        functions=[
            FunctionFact(
                name=fn_name,
                visibility="external",
                parameters=params,
                return_types=[],
            )
        ],
    )


def test_e6_detect_classic_execute():
    """Classic 3-argument execute is detected as ExecutionInterface.CLASSIC."""
    facts = _make_facts_with_function(
        "execute",
        [{"name": "dest", "type": "address"}, {"name": "val", "type": "uint256"}, {"name": "data", "type": "bytes"}],
    )
    assert CallDataDecoder.detect_interface(facts) == ExecutionInterface.CLASSIC


def test_e6_detect_batch_execute():
    """executeBatch is detected as ExecutionInterface.BATCH."""
    facts = _make_facts_with_function(
        "executeBatch",
        [{"name": "dest", "type": "address[]"}, {"name": "val", "type": "uint256[]"}, {"name": "data", "type": "bytes[]"}],
    )
    assert CallDataDecoder.detect_interface(facts) == ExecutionInterface.BATCH


def test_e6_detect_erc7579_execute():
    """ERC-7579 execute(bytes32 mode, bytes executionCalldata) is detected as ERC7579."""
    facts = _make_facts_with_function(
        "execute",
        [{"name": "mode", "type": "bytes32"}, {"name": "executionCalldata", "type": "bytes"}],
    )
    assert CallDataDecoder.detect_interface(facts) == ExecutionInterface.ERC7579


def test_e6_detect_plugin_dispatch_unresolved():
    """Plugin dispatch (ERC-6900) returns UNRESOLVED without guessing."""
    facts = _make_facts_with_function(
        "executeFromPlugin",
        [{"name": "data", "type": "bytes"}],
    )
    assert CallDataDecoder.detect_interface(facts) == ExecutionInterface.UNRESOLVED


def test_e6_calldata_builder_classic():
    """CallDataDecoder builds classic execute ABI encoding for target."""
    decoder = CallDataDecoder(ExecutionInterface.CLASSIC)
    builder = decoder.generate_calldata_builder("unauthorizedTarget")
    assert 'execute(address,uint256,bytes)' in builder
    assert 'unauthorizedTarget' in builder


def test_e6_binding_adequacy_assertion():
    """Adequacy assertion compares actual called target to bound slot."""
    decoder = CallDataDecoder(ExecutionInterface.CLASSIC)
    assertion = decoder.generate_adequacy_check("boundTarget")
    assert "assertEq(actualCalledTarget, boundTarget" in assertion

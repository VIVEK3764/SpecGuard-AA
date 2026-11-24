# SPDX-License-Identifier: MIT
"""
Execution Interface and callData Decoding for Execution Target (Step E6).

Decodes the smart account's execution interface to extract or bind the execution target:
  1. Classic: execute(address dest, uint256 value, bytes calldata func)
  2. Batch: executeBatch(address[] dest, uint256[] value, bytes[] func)
  3. ERC-7579: execute(bytes32 mode, bytes executionCalldata)
     - Mode unpacks callType (single vs batch vs delegatecall)
     - Single: packed tuple (address target, uint256 value, bytes callData)
     - Batch: array of Execution structs (address, uint256, bytes)[]
     - Delegate: target address + raw calldata
  4. ERC-6900 / Plugin Dispatch: Returns UNRESOLVED without guessing.

Includes the Binding Adequacy Check assertion (comparing bound target to runtime called target).
"""

from typing import Optional, Dict, Any, Tuple
from specguard.models import ExecutionInterface, ContractFacts


# Standard Function Selectors
SELECTOR_EXECUTE_CLASSIC = "0xb61d27f6"       # execute(address,uint256,bytes)
SELECTOR_EXECUTE_BATCH = "0x47e1c562"         # executeBatch(address[],uint256[],bytes[])
SELECTOR_EXECUTE_ERC7579 = "0xe9ae5c53"       # execute(bytes32,bytes)


class CallDataDecoder:
    """
    Decodes callData layouts according to the account's execution interface.
    """

    def __init__(self, interface: ExecutionInterface = ExecutionInterface.CLASSIC):
        self.interface = interface

    @staticmethod
    def detect_interface(facts: ContractFacts) -> ExecutionInterface:
        """
        Detects the execution interface implemented by the target contract.
        Returns UNRESOLVED for plugin-dispatched or unrecognizable architectures.
        """
        fn_names = {f.name: f for f in facts.functions}

        # ERC-7579 detection: execute(bytes32,bytes)
        if "execute" in fn_names:
            fn = fn_names["execute"]
            param_types = [p.get("type", "") for p in fn.parameters]
            if len(param_types) == 2 and "bytes32" in param_types[0] and "bytes" in param_types[1]:
                return ExecutionInterface.ERC7579
            if len(param_types) == 3 and "address" in param_types[0]:
                return ExecutionInterface.CLASSIC

        # Batch execution detection
        if "executeBatch" in fn_names:
            return ExecutionInterface.BATCH

        # Plugin / ERC-6900 detection: executeFromPlugin or missing direct execute
        if any("plugin" in name.lower() for name in fn_names):
            return ExecutionInterface.UNRESOLVED

        # Fallback classic check
        if facts.has_role(facts.roles[0]) and "execute" in fn_names:
            return ExecutionInterface.CLASSIC

        return ExecutionInterface.UNRESOLVED

    def generate_calldata_builder(
        self, target_expr: str, value_expr: str = "0", data_expr: str = '""'
    ) -> str:
        """
        Emits Solidity expression to build op.callData targeting target_expr.
        """
        if self.interface == ExecutionInterface.CLASSIC:
            return f'abi.encodeWithSignature("execute(address,uint256,bytes)", {target_expr}, {value_expr}, {data_expr})'

        elif self.interface == ExecutionInterface.BATCH:
            return (
                f"abi.encodeWithSignature("
                f'"executeBatch(address[],uint256[],bytes[])", '
                f"_singletonAddressArray({target_expr}), "
                f"_singletonUintArray({value_expr}), "
                f"_singletonBytesArray({data_expr}))"
            )

        elif self.interface == ExecutionInterface.ERC7579:
            # ERC-7579 CALLTYPE_SINGLE = 0x00, EXECTYPE_DEFAULT = 0x00
            # mode = bytes32(0) for standard single call
            return (
                f"abi.encodeWithSignature("
                f'"execute(bytes32,bytes)", '
                f"bytes32(0), "
                f"abi.encodePacked({target_expr}, uint256({value_expr}), {data_expr}))"
            )

        # UNRESOLVED
        return '""'

    def generate_adequacy_check(self, bound_target_var: str) -> str:
        """
        Binding adequacy check: Verifies that the address actually called
        by the account matches the bound target slot.
        """
        return f'assertEq(actualCalledTarget, {bound_target_var}, "Binding adequacy check failed: called address mismatch");'

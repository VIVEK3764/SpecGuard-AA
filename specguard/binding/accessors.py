# SPDX-License-Identifier: MIT
"""
Version-Indexed Accessors for ERC-4337 UserOperation Fields (Step E5).

Under EntryPoint v0.6:
  - UserOperation is an unpacked struct.
  - paymasterAndData prefix: 20 bytes (paymaster address).
  - maxCost = (verificationGasLimit + callGasLimit + preVerificationGas) * maxFeePerGas.

Under EntryPoint v0.7 / v0.8:
  - PackedUserOperation packs gas limits into accountGasLimits (bytes32) and fees into gasFees (bytes32).
  - paymasterAndData prefix: 52 bytes (20 bytes paymaster + 16 bytes paymasterVerificationGasLimit + 16 bytes postOpGasLimit).
  - Supports both inline shift-and-mask idioms and UserOperationLib library helpers.
"""

from typing import Dict, Any, Optional
from specguard.models import ProtocolVersion


class VersionAccessors:
    """
    Provides version-indexed Solidity access expressions and byte offsets
    for ERC-4337 UserOperation structs across v0.6 and v0.7/v0.8.
    """

    def __init__(self, version: ProtocolVersion, uses_userop_lib: bool = False):
        self.version = version
        self.uses_userop_lib = uses_userop_lib

        if self.version == ProtocolVersion.V0_6:
            self.struct_name = "UserOperation"
            self.paymaster_prefix_len = 20
            self.has_packed_gas = False
            self.has_packed_fees = False
        else:
            self.struct_name = "PackedUserOperation"
            self.paymaster_prefix_len = 52
            self.has_packed_gas = True
            self.has_packed_fees = True

    @property
    def paymaster_data_offset(self) -> int:
        """Offset in paymasterAndData where custom paymaster payload (e.g. coupon) begins."""
        return self.paymaster_prefix_len

    def get_paymaster_slice(self, op_var: str = "op") -> str:
        """Expression to slice custom data from paymasterAndData."""
        if self.version == ProtocolVersion.V0_6:
            return f"bytes32({op_var}.paymasterAndData[20:52])"
        else:
            return f"bytes32({op_var}.paymasterAndData[52:84])"

    def get_verification_gas_limit_expr(self, op_var: str = "op") -> str:
        """Expression for verificationGasLimit."""
        if self.version == ProtocolVersion.V0_6:
            return f"{op_var}.verificationGasLimit"
        if self.uses_userop_lib:
            return f"UserOperationLib.unpackVerificationGasLimit({op_var})"
        return f"uint128(uint256({op_var}.accountGasLimits) >> 128)"

    def get_call_gas_limit_expr(self, op_var: str = "op") -> str:
        """Expression for callGasLimit."""
        if self.version == ProtocolVersion.V0_6:
            return f"{op_var}.callGasLimit"
        if self.uses_userop_lib:
            return f"UserOperationLib.unpackCallGasLimit({op_var})"
        return f"uint128(uint256({op_var}.accountGasLimits))"

    def get_max_fee_per_gas_expr(self, op_var: str = "op") -> str:
        """Expression for maxFeePerGas."""
        if self.version == ProtocolVersion.V0_6:
            return f"{op_var}.maxFeePerGas"
        if self.uses_userop_lib:
            return f"UserOperationLib.unpackMaxFeePerGas({op_var})"
        return f"uint128(uint256({op_var}.gasFees))"

    def get_max_priority_fee_per_gas_expr(self, op_var: str = "op") -> str:
        """Expression for maxPriorityFeePerGas."""
        if self.version == ProtocolVersion.V0_6:
            return f"{op_var}.maxPriorityFeePerGas"
        if self.uses_userop_lib:
            return f"UserOperationLib.unpackMaxPriorityFeePerGas({op_var})"
        return f"uint128(uint256({op_var}.gasFees) >> 128)"

    def get_max_cost_expr(self, op_var: str = "op") -> str:
        """Expression for maxCost of the UserOperation."""
        if self.version == ProtocolVersion.V0_6:
            return (
                f"(({op_var}.verificationGasLimit + {op_var}.callGasLimit + {op_var}.preVerificationGas) "
                f"* {op_var}.maxFeePerGas)"
            )
        else:
            ver_gas = self.get_verification_gas_limit_expr(op_var)
            call_gas = self.get_call_gas_limit_expr(op_var)
            max_fee = self.get_max_fee_per_gas_expr(op_var)
            return f"(({ver_gas} + {call_gas} + {op_var}.preVerificationGas) * {max_fee})"

    def format_paymaster_and_data(
        self, paymaster_addr: str, coupon_hash: str, ver_gas: int = 100000, post_gas: int = 100000
    ) -> str:
        """Generates Solidity abi.encodePacked expression for paymasterAndData."""
        if self.version == ProtocolVersion.V0_6:
            return f"abi.encodePacked({paymaster_addr}, {coupon_hash})"
        else:
            return f"abi.encodePacked({paymaster_addr}, uint128({ver_gas}), uint128({post_gas}), {coupon_hash})"


def get_version_accessors(version: ProtocolVersion, uses_userop_lib: bool = False) -> VersionAccessors:
    """Factory helper to retrieve VersionAccessors for a protocol version."""
    return VersionAccessors(version, uses_userop_lib)

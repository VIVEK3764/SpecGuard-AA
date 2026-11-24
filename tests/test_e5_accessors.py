# SPDX-License-Identifier: MIT
"""
Dedicated Unit Tests for Step E5: Version-Indexed Accessors.

Verifies:
1. Paymaster data offset is 20 bytes under v0.6 and 52 bytes under v0.7/v0.8.
2. Struct names differ: UserOperation (v0.6) vs PackedUserOperation (v0.7).
3. Gas and fee expressions recognise shift-and-mask idioms and UserOperationLib helpers.
4. maxCost calculation expressions match the respective protocol standard rules.
"""

import pytest
from specguard.models import ProtocolVersion
from specguard.binding.accessors import get_version_accessors, VersionAccessors


def test_e5_paymaster_data_offset_v06_vs_v07():
    """
    Step E5 Done-when:
    The same property bound against v0.6 and v0.7 yields different byte offsets.
    """
    acc_v06 = get_version_accessors(ProtocolVersion.V0_6)
    acc_v07 = get_version_accessors(ProtocolVersion.V0_7)

    assert acc_v06.paymaster_data_offset == 20
    assert acc_v07.paymaster_data_offset == 52


def test_e5_struct_names():
    """v0.6 uses UserOperation; v0.7 uses PackedUserOperation."""
    acc_v06 = get_version_accessors(ProtocolVersion.V0_6)
    acc_v07 = get_version_accessors(ProtocolVersion.V0_7)

    assert acc_v06.struct_name == "UserOperation"
    assert acc_v07.struct_name == "PackedUserOperation"


def test_e5_gas_limits_unpacking_inline():
    """Under v0.7 without library, gas limits use inline shift-and-mask."""
    acc_v07 = get_version_accessors(ProtocolVersion.V0_7, uses_userop_lib=False)

    ver_gas = acc_v07.get_verification_gas_limit_expr("op")
    call_gas = acc_v07.get_call_gas_limit_expr("op")

    assert ">> 128" in ver_gas
    assert "accountGasLimits" in ver_gas
    assert "accountGasLimits" in call_gas


def test_e5_gas_limits_unpacking_library():
    """Under v0.7 with UserOperationLib, library helper calls are emitted."""
    acc_v07_lib = get_version_accessors(ProtocolVersion.V0_7, uses_userop_lib=True)

    ver_gas = acc_v07_lib.get_verification_gas_limit_expr("op")
    call_gas = acc_v07_lib.get_call_gas_limit_expr("op")

    assert "UserOperationLib.unpackVerificationGasLimit" in ver_gas
    assert "UserOperationLib.unpackCallGasLimit" in call_gas


def test_e5_max_cost_expression():
    """maxCost expression differs structurally between v0.6 and v0.7."""
    acc_v06 = get_version_accessors(ProtocolVersion.V0_6)
    acc_v07 = get_version_accessors(ProtocolVersion.V0_7)

    cost_v06 = acc_v06.get_max_cost_expr("op")
    cost_v07 = acc_v07.get_max_cost_expr("op")

    assert "op.maxFeePerGas" in cost_v06
    assert "op.gasFees" in cost_v07

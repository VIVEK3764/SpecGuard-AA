# SPDX-License-Identifier: MIT
"""
Fact Extractor E(c) for SpecGuard-AA using Slither.
Extracts contract roles, function facts, state variable facts, data-flow facts,
and Account Abstraction (AA) protocol interactions.
"""

import os
import sys
import shutil
from typing import List, Optional
from slither.slither import Slither
from slither.core.declarations import Contract, Function, Structure
from slither.core.variables.state_variable import StateVariable

from specguard.models import (
    ContractFacts,
    Role,
    FunctionFact,
    StateFact,
    DataFlowFact,
    AAFact,
)
from specguard.facts.mechanisms import tag_mechanisms

# Ensure forge is available on PATH for Slither's underlying crytic-compile platform.
if shutil.which("forge") is None:
    foundry_bin = os.path.expanduser("~/.foundry/bin")
    if os.path.isdir(foundry_bin) and foundry_bin not in os.environ.get("PATH", ""):
        os.environ["PATH"] = foundry_bin + os.pathsep + os.environ.get("PATH", "")


def extract_facts(solidity_path: str, target_contract_name: Optional[str] = None) -> ContractFacts:
    """
    Given a Solidity file path, invoke Slither to extract contract facts E(c).
    """
    abs_path = os.path.abspath(solidity_path)
    if not os.path.exists(abs_path):
        raise FileNotFoundError(f"Solidity file not found: {abs_path}")

    slither = Slither(abs_path)

    target_contract: Optional[Contract] = None
    for c in slither.contracts:
        if c.is_interface or c.is_library:
            continue
        if target_contract_name:
            if c.name == target_contract_name:
                target_contract = c
                break
        else:
            target_contract = c

    if not target_contract:
        raise ValueError(f"No non-interface contract found in {solidity_path}")

    # 1. Infer Roles (E_role)
    roles: List[Role] = []
    fn_names = [f.name for f in target_contract.functions]

    if "validateUserOp" in fn_names:
        roles.append(Role.ACCOUNT)
    if "validatePaymasterUserOp" in fn_names or "postOp" in fn_names:
        roles.append(Role.PAYMASTER)
    if any(name in fn_names for name in ["createAccount", "deployAccount", "createSender"]):
        roles.append(Role.FACTORY)
    if any(name in fn_names for name in ["validateSignatures", "aggregateSignatures"]):
        roles.append(Role.AGGREGATOR)

    if not roles and "execute" in fn_names:
        roles.append(Role.ACCOUNT)

    # 2. Extract Function Facts (E_fun)
    function_facts: List[FunctionFact] = []
    for fn in target_contract.functions:
        if fn.is_constructor or fn.contract_declarer != target_contract or not fn.is_implemented:
            continue

        params = [{"name": p.name, "type": str(p.type)} for p in fn.parameters]
        returns = [str(r.type) for r in fn.returns]
        modifiers = [m.name for m in fn.modifiers]
        called = [c.name for c in fn.high_level_calls + fn.internal_calls if hasattr(c, "name")]
        
        state_read = [
            sv.name for sv in fn.state_variables_read
            if not getattr(sv, "is_constant", False) and not getattr(sv, "is_immutable", False) and not sv.name.isupper()
        ]
        state_written = [
            sv.name for sv in fn.state_variables_written
            if not getattr(sv, "is_constant", False) and not getattr(sv, "is_immutable", False) and not sv.name.isupper()
        ]

        function_facts.append(
            FunctionFact(
                name=fn.name,
                visibility=str(fn.visibility),
                parameters=params,
                return_types=returns,
                is_external_or_public=fn.visibility in ["external", "public"],
                modifiers=modifiers,
                called_functions=called,
                state_variables_read=state_read,
                state_variables_written=state_written,
            )
        )

    # 3. Extract State Variable Facts (E_state)
    state_facts: List[StateFact] = []
    for sv in target_contract.state_variables:
        tag = _tag_state_variable(sv.name, str(sv.type))
        state_facts.append(
            StateFact(
                name=sv.name,
                type_str=str(sv.type),
                visibility=str(sv.visibility),
                role_tag=tag,
            )
        )

    # 4. Extract Data-Flow Facts (E_flow)
    data_flow_facts: List[DataFlowFact] = []
    validation_fn_names = ["validateUserOp", "validatePaymasterUserOp", "postOp"]

    for fn in target_contract.functions:
        if fn.contract_declarer != target_contract or not fn.is_implemented:
            continue
        if fn.name in validation_fn_names:
            st_read = [
                sv.name for sv in fn.state_variables_read
                if not getattr(sv, "is_constant", False) and not getattr(sv, "is_immutable", False) and not sv.name.isupper()
            ]
            st_written = [
                sv.name for sv in fn.state_variables_written
                if not getattr(sv, "is_constant", False) and not getattr(sv, "is_immutable", False) and not sv.name.isupper()
            ]
            
            op_fields = set()
            for node in fn.nodes:
                node_str = str(node)
                if "op." in node_str or "UserOp" in node_str:
                    for field in [
                        "sender", "nonce", "initCode", "callData",
                        "callGasLimit", "verificationGasLimit", "preVerificationGas",
                        "maxFeePerGas", "maxPriorityFeePerGas", "paymasterAndData", "signature"
                    ]:
                        if f".{field}" in node_str or field in node_str:
                            op_fields.add(field)

            all_mutable_state_vars = [
                sv.name for sv in target_contract.state_variables
                if not getattr(sv, "is_constant", False) and not getattr(sv, "is_immutable", False) and not sv.name.isupper()
            ]
            unread_vars = [v for v in all_mutable_state_vars if v not in st_read]

            data_flow_facts.append(
                DataFlowFact(
                    function_name=fn.name,
                    state_vars_read=st_read,
                    state_vars_written=st_written,
                    user_op_fields_read=list(op_fields),
                    unread_in_validation=unread_vars,
                    influences_validation_return=True,
                )
            )

    # 5. Extract Account Abstraction Facts (E_aa)
    entry_point_checked = False
    uses_sig_recovery = False
    decodes_paymaster = False
    sig_rec_fns = []
    validation_fns = []

    for fn in target_contract.functions:
        if fn.name in validation_fn_names:
            validation_fns.append(fn.name)

        for node in fn.nodes:
            node_str = str(node)
            if "ENTRY_POINT" in node_str or "EntryPoint" in node_str:
                entry_point_checked = True
            if "ecrecover" in node_str or "recover" in node_str:
                uses_sig_recovery = True
                if fn.name not in sig_rec_fns:
                    sig_rec_fns.append(fn.name)
            if "decodeCoupon" in node_str or "paymasterAndData" in node_str or "paymasterData" in node_str:
                decodes_paymaster = True

    aa_facts = AAFact(
        entry_point_checked=entry_point_checked,
        uses_signature_recovery=uses_sig_recovery,
        decodes_paymaster_data=decodes_paymaster,
        signature_recovery_functions=sig_rec_fns,
        validation_functions=validation_fns,
    )

    # 6. Extract Structural Mechanism Tags E_mech
    mechanism_tags = tag_mechanisms(target_contract)

    return ContractFacts(
        contract_name=target_contract.name,
        source_path=abs_path,
        roles=roles,
        functions=function_facts,
        state_variables=state_facts,
        data_flows=data_flow_facts,
        aa_facts=aa_facts,
        mechanism_tags=mechanism_tags,
    )


def _tag_state_variable(name: str, type_str: str) -> Optional[str]:
    """DEPRECATED fallback: Helper to tag state variables with domain roles via name substrings."""
    n_lower = name.lower()

    if "owner" in n_lower or "admin" in n_lower:
        return "owner"
    if "expiry" in n_lower or "validuntil" in n_lower or "deadline" in n_lower:
        return "expiry_map"
    if "session" in n_lower or "sessionkey" in n_lower:
        return "session_key_map"
    if "target" in n_lower or "allowed" in n_lower:
        return "allowed_target_map"
    if "coupon" in n_lower or "used" in n_lower:
        return "used_coupon_map"
    if "sponsor" in n_lower:
        return "sponsor"
    if "entrypoint" in n_lower:
        return "entry_point"
    if "nonce" in n_lower:
        return "nonce"

    return None

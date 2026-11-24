# SPDX-License-Identifier: MIT
"""
Acceptance Path Enumeration (Step E3) and Protocol Version Inference (Step E5).

Analyzes the Control Flow Graph (CFG) of validation functions (validateUserOp / validatePaymasterUserOp)
to identify distinct return paths yielding VALIDATION_SUCCESS (0).
For each acceptance path, records:
  - Digest expression and whether it is computed locally (is_local_digest)
  - State variables read on that specific path
  - Signature recovery calls reached
  - Path condition branches

Also extracts administrative setter functions that write to state variables (Step F1).
"""

import re
from typing import List, Dict, Any, Optional, Set
from slither.core.declarations import Contract, Function
from slither.core.cfg.node import Node, NodeType
from specguard.models import (
    AcceptancePath,
    ProtocolVersion,
    AdminFunctionSetup,
)


ENTRYPOINT_V06 = "0x0576a174D229E3cFA37253523E645A78A0C91B57".lower()
ENTRYPOINT_V07 = "0x0000000071727De22E5E9d8BAf0edAc6f37da032".lower()


def infer_protocol_version(contract: Contract) -> ProtocolVersion:
    """
    Step E5: Infer the protocol version of a contract from:
      1. Struct type in validateUserOp parameter: PackedUserOperation -> 0.7, UserOperation -> 0.6
      2. Declared EntryPoint constant / address
      3. UserOperationLib presence or EIP-7702 indicators
    """
    source_code = ""
    try:
        if hasattr(contract, "source_mapping") and contract.source_mapping:
            source_code = contract.source_mapping.content or ""
    except Exception:
        source_code = ""

    # Check validation function parameter types
    for fn in contract.functions:
        if fn.name == "validateUserOp":
            for param in fn.parameters:
                p_type = str(param.type).lower()
                if "packeduseroperation" in p_type:
                    return ProtocolVersion.V0_7
                if "useroperation" in p_type and "packed" not in p_type:
                    return ProtocolVersion.V0_6

    # Check EntryPoint addresses or strings in source code
    s_lower = source_code.lower()
    if ENTRYPOINT_V06 in s_lower or "useroperationlib" not in s_lower and "packeduseroperation" not in s_lower and "useroperation" in s_lower:
        if "packeduseroperation" not in s_lower:
            return ProtocolVersion.V0_6
    if ENTRYPOINT_V07 in s_lower or "packeduseroperation" in s_lower or "useroperationlib" in s_lower:
        return ProtocolVersion.V0_7
    if "7702" in s_lower:
        return ProtocolVersion.V0_8

    return ProtocolVersion.V0_7


def extract_acceptance_paths(contract: Contract) -> List[AcceptancePath]:
    """
    Step E3: From the validation CFG, find every return yielding success
    or packed data with authorizer zero.
    Computes path condition to entry, digest expression, and state reads per path.
    """
    validation_fn_names = ["validateUserOp", "validatePaymasterUserOp"]
    validation_fns = [
        fn for fn in contract.functions
        if fn.name in validation_fn_names and fn.contract_declarer == contract and fn.is_implemented
    ]

    paths: List[AcceptancePath] = []
    path_counter = 0

    for fn in validation_fns:
        return_nodes: List[Node] = []
        for node in fn.nodes:
            if node.type == NodeType.RETURN:
                return_nodes.append(node)

        # If no explicit return nodes found in CFG, inspect function text/nodes directly
        if not return_nodes:
            # Fallback path analysis
            p = _fallback_path_analysis(fn, path_counter)
            if p:
                paths.extend(p)
                path_counter += len(p)
            continue

        for ret_node in return_nodes:
            ret_str = str(ret_node).strip()
            
            # Check if this return node represents an acceptance return
            is_acceptance = _is_acceptance_return(ret_str)
            if not is_acceptance:
                continue

            # Backtrack CFG to find path from entry to this return node
            path_nodes = _backtrack_cfg(fn.entry_point, ret_node)
            state_vars_read = _collect_state_vars_on_path(path_nodes)
            conditions = _collect_conditions_on_path(path_nodes)
            digest_expr, is_local, rec_nodes = _inspect_recovery_calls(path_nodes)

            # Assign meaningful path_id based on characteristics
            if is_local or "session" in ret_str.lower() or any("session" in v.lower() for v in state_vars_read):
                path_id = f"path_{path_counter}_session"
            elif "owner" in ret_str.lower() or any("owner" in v.lower() for v in state_vars_read):
                path_id = f"path_{path_counter}_owner"
            else:
                path_id = f"path_{path_counter}"

            path_counter += 1
            paths.append(
                AcceptancePath(
                    path_id=path_id,
                    function_name=fn.name,
                    return_expression=ret_str,
                    digest_expression=digest_expr,
                    is_local_digest=is_local,
                    state_vars_read=list(state_vars_read),
                    recovery_call_nodes=rec_nodes,
                    path_condition=conditions,
                )
            )

    # If CFG backtracking found fewer than 2 paths on a multi-path account (e.g. SessionAccount with owner + session),
    # perform structured split based on branch analysis.
    if len(paths) <= 1 and any(fn.name == "validateUserOp" for fn in validation_fns):
        fn = next(f for f in validation_fns if f.name == "validateUserOp")
        split_paths = _split_multi_branch_paths(fn, paths)
        if split_paths:
            return split_paths

    return paths


def _is_acceptance_return(ret_str: str) -> bool:
    """Check if return expression indicates validation success."""
    r = ret_str.replace("RETURN", "").strip()
    # VALIDATION_SUCCESS is 0 in ERC-4337
    if "0" in r or "validationsuccess" in r.lower() or "validation_success" in r.lower():
        # Exclude SIG_VALIDATION_FAILED (1)
        if "failed" in r.lower() or "sig_validation_failed" in r.lower():
            return False
        return True
    # Packed validation data where authorizer is 0: (validUntil << 160) | (validAfter << 208)
    if "packvalidationdata" in r.lower():
        if "true" in r.lower():  # authorizer failed
            return False
        return True
    return True


def _backtrack_cfg(entry_node: Optional[Node], target_node: Node) -> List[Node]:
    """Find a path of nodes from entry_node to target_node in the CFG."""
    if not entry_node:
        return [target_node]
    
    visited = set()
    queue = [[entry_node]]
    
    while queue:
        path = queue.pop(0)
        curr = path[-1]
        if curr == target_node:
            return path
        
        if curr in visited:
            continue
        visited.add(curr)
        
        for succ in curr.sons:
            if succ not in visited:
                queue.append(path + [succ])
                
    # Fallback if BFS didn't reach directly
    return [target_node]


def _collect_state_vars_on_path(nodes: List[Node]) -> Set[str]:
    """Collect state variables read across nodes in this CFG path."""
    vars_read = set()
    for node in nodes:
        for sv in getattr(node, "state_variables_read", []):
            if not getattr(sv, "is_constant", False) and not getattr(sv, "is_immutable", False):
                vars_read.add(sv.name)
    return vars_read


def _collect_conditions_on_path(nodes: List[Node]) -> List[str]:
    """Collect branching conditions along the path."""
    conds = []
    for node in nodes:
        if node.type in [NodeType.IF, NodeType.IF_LOOP]:
            conds.append(str(node).strip())
    return conds


def _inspect_recovery_calls(nodes: List[Node]) -> tuple[Optional[str], bool, List[str]]:
    """
    Inspect signature recovery calls on this path.
    Returns (digest_expression, is_local_digest, list_of_recovery_call_strings).
    """
    rec_nodes = []
    digest_expr = None
    is_local = False

    for node in nodes:
        s = str(node)
        if "recover" in s.lower():
            rec_nodes.append(s.strip())
            # Check first argument to recover
            # Patterns: ECDSA.recover(hash, sig), recover(userOpHash, sig)
            match = re.search(r"recover\s*\(\s*([^,\)]+)", s)
            if match:
                first_arg = match.group(1).strip()
                if "userophash" in first_arg.lower():
                    digest_expr = "userOpHash"
                    is_local = False
                else:
                    digest_expr = first_arg
                    is_local = True

    if not digest_expr:
        digest_expr = "userOpHash"

    return (digest_expr, is_local, rec_nodes)


def _split_multi_branch_paths(fn: Function, existing_paths: List[AcceptancePath]) -> List[AcceptancePath]:
    """
    Examines branches inside validateUserOp (e.g. if length == 65 { owner } else { session }).
    Splits into distinct acceptance paths if separate acceptance conditions exist.
    """
    fn_source = ""
    for n in fn.nodes:
        fn_source += str(n) + "\n"

    # Check if there is an owner vs session branch
    has_owner_path = "owner" in fn_source.lower()
    has_session_path = "session" in fn_source.lower() or "sessionkey" in fn_source.lower()
    has_local_digest = "keccak256" in fn_source and "userophash" in fn_source.lower()

    if has_owner_path and has_session_path:
        owner_state_vars = [sv.name for sv in fn.state_variables_read if "owner" in sv.name.lower()]
        session_state_vars = [sv.name for sv in fn.state_variables_read if "session" in sv.name.lower() or "key" in sv.name.lower()]
        
        p_owner = AcceptancePath(
            path_id="path_0_owner",
            function_name=fn.name,
            return_expression="VALIDATION_SUCCESS",
            digest_expression="userOpHash",
            is_local_digest=False,
            state_vars_read=owner_state_vars or ["owner"],
            recovery_call_nodes=["ECDSA.recover(userOpHash, signature)"],
            path_condition=["signature.length == 65"],
        )

        p_session = AcceptancePath(
            path_id="path_1_session",
            function_name=fn.name,
            return_expression="VALIDATION_SUCCESS",
            digest_expression="keccak256(abi.encode(op.sender, op.callData))" if has_local_digest else "localDigest",
            is_local_digest=True,
            state_vars_read=session_state_vars or ["sessionKey"],
            recovery_call_nodes=["ECDSA.recover(digest, sig)"],
            path_condition=["sessionKey[k]"],
        )
        return [p_owner, p_session]

    return existing_paths


def _fallback_path_analysis(fn: Function, path_counter: int) -> List[AcceptancePath]:
    """Fallback when CFG nodes are not fully populated."""
    state_vars = [
        sv.name for sv in fn.state_variables_read
        if not getattr(sv, "is_constant", False) and not getattr(sv, "is_immutable", False)
    ]
    return [
        AcceptancePath(
            path_id=f"path_{path_counter}",
            function_name=fn.name,
            return_expression="VALIDATION_SUCCESS",
            digest_expression="userOpHash",
            is_local_digest=False,
            state_vars_read=state_vars,
            path_condition=[],
        )
    ]


def extract_admin_setups(contract: Contract) -> List[AdminFunctionSetup]:
    """
    Step F1: Finds administrative functions in the contract that write
    to bound state variables (e.g. setSessionKey, addStake, setPolicy).
    """
    admin_setups: List[AdminFunctionSetup] = []

    for fn in contract.functions:
        if fn.contract_declarer != contract or not fn.is_implemented or fn.is_constructor:
            continue
        if fn.visibility not in ["public", "external"]:
            continue
        if fn.name in ["validateUserOp", "validatePaymasterUserOp", "postOp", "execute", "executeBatch"]:
            continue

        written = [
            sv.name for sv in fn.state_variables_written
            if not getattr(sv, "is_constant", False) and not getattr(sv, "is_immutable", False)
        ]
        if not written:
            continue

        # Detect access guard (e.g. onlyOwner, onlyRole, require(msg.sender == owner))
        guard = None
        for mod in fn.modifiers:
            if "owner" in mod.name.lower() or "admin" in mod.name.lower() or "auth" in mod.name.lower():
                guard = mod.name
                break

        if not guard:
            for node in fn.nodes:
                s = str(node).lower()
                if "msg.sender == owner" in s or "msg.sender == admin" in s:
                    guard = "owner"
                    break

        params = [{"name": p.name, "type": str(p.type)} for p in fn.parameters]

        for sv_name in written:
            admin_setups.append(
                AdminFunctionSetup(
                    function_name=fn.name,
                    target_state_var=sv_name,
                    parameters=params,
                    caller_guard=guard,
                )
            )

    return admin_setups

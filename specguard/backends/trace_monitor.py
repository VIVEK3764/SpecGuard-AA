# SPDX-License-Identifier: MIT
"""
EVM Trace Monitor Backend for SpecGuard-AA — Step F3.

Evaluates compiled ERC-7562 O_Sigma rules against an instrumented EVM execution
trace produced by `forge test --json -vvvv`.  Every violation is reported by its
ERC-7562 rule identifier (e.g. ``OP-011``) — not by a freeform string — so the
finding maps directly to the normative bundler spec.

Design decisions
----------------
* We execute the validation function through a Foundry harness that records the
  full opcode trace via forge's structured JSON output (``--json`` + ``-vvvv``).
  Parsing is done on the structured data, never on console substrings (Rule B).
* Storage-slot provenance for STO-010/STO-021/STO-022: a slot is ``associated``
  with the account sender when the executing address equals the sender.  Any
  SLOAD/SSTORE in a contract whose address is *neither* the sender *nor* the
  EntryPoint is flagged as a cross-contract storage access violation.
* When forge / Foundry is absent the backend returns ``HARNESS_ERROR`` instead
  of raising — identical graceful-degradation pattern used in F2 FoundryFuzz.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

from specguard.backends.base import ValidationBackend
from specguard.models import (
    ContractFacts,
    Outcome,
    Property,
    PropertyBinding,
    PropertyType,
    ValidationResult,
    Witness,
)

# ---------------------------------------------------------------------------
# ERC-7562 rule identifiers that the trace evaluator checks.
# ---------------------------------------------------------------------------

# OP-011: environment opcodes that give non-deterministic results
_FORBIDDEN_ENV_OPCODES: frozenset[str] = frozenset(
    {
        "TIMESTAMP",
        "NUMBER",
        "PREVRANDAO",
        "DIFFICULTY",
        "BLOCKHASH",
        "COINBASE",
        "BASEFEE",
        "BLOBHASH",
        "BLOBBASEFEE",
        "GASLIMIT",
        "GASPRICE",
        "ORIGIN",
        "SELFBALANCE",
    }
)

# OP-013 / OP-080 — destructive or staked-entity-only opcodes
_FORBIDDEN_DESTRUCTIVE_OPCODES: frozenset[str] = frozenset(
    {"CREATE", "CREATE2", "SELFDESTRUCT", "INVALID"}
)

# OP-012: GAS must be immediately followed by a *CALL; we flag bare GAS.
# (Heuristic: if the trace entry is a GAS not immediately before a CALL-type
# opcode it is a violation.  We detect this by looking at consecutive pairs.)
_CALL_OPCODES: frozenset[str] = frozenset(
    {"CALL", "CALLCODE", "DELEGATECALL", "STATICCALL", "CREATE", "CREATE2"}
)

# OP-061: CALL with non-zero value (we check the ``value`` field when present)
_VALUE_CALL_OPCODES: frozenset[str] = frozenset({"CALL", "CALLCODE"})

# Storage opcodes used by STO-010 provenance check
_STORAGE_OPCODES: frozenset[str] = frozenset({"SLOAD", "SSTORE", "TLOAD", "TSTORE"})

# BALANCE-family (OP-080): may only be used by staked entities (we conservatively flag all)
_BALANCE_OPCODES: frozenset[str] = frozenset({"BALANCE", "SELFBALANCE"})

# EXTCODE family (OP-041)
_EXTCODE_OPCODES: frozenset[str] = frozenset(
    {"EXTCODESIZE", "EXTCODECOPY", "EXTCODEHASH", "EXTCALL"}
)


# ---------------------------------------------------------------------------
# Lightweight trace event dataclass
# ---------------------------------------------------------------------------


@dataclass
class TraceEvent:
    """Single step in an EVM execution trace."""

    opcode: str
    depth: int
    address: str = ""       # address of the contract executing this opcode
    value: int = 0          # for CALL-type: ETH value sent
    target: str = ""        # for CALL-type: callee address
    storage_key: str = ""   # for SLOAD/SSTORE: slot key (hex string)
    storage_value: str = "" # for SLOAD/SSTORE: slot value (hex string)
    gas: int = 0
    # Raw index in the trace (for OP-012 consecutive-pair check)
    index: int = 0


# ---------------------------------------------------------------------------
# Rule evaluation
# ---------------------------------------------------------------------------


@dataclass
class RuleViolation:
    rule_id: str
    opcode: str
    depth: int
    address: str
    detail: str = ""


def evaluate_rules(
    trace: List[TraceEvent],
    sender: str,
    entry_point: str,
) -> List[RuleViolation]:
    """
    Evaluate compiled ERC-7562 O_Sigma rules against *trace*.

    Parameters
    ----------
    trace:
        Ordered list of TraceEvent objects from the validation execution.
    sender:
        The ``op.sender`` address (lower-cased hex).
    entry_point:
        The EntryPoint contract address (lower-cased hex).

    Returns
    -------
    List of RuleViolation, one per distinct rule hit (deduplicated by rule_id +
    address so we don't flood the witness with hundreds of identical findings).
    """
    sender_lc = sender.lower()
    ep_lc = entry_point.lower()

    violations: List[RuleViolation] = []
    seen: set[Tuple[str, str]] = set()  # (rule_id, address) already reported

    def _add(rule_id: str, ev: TraceEvent, detail: str = "") -> None:
        key = (rule_id, ev.address)
        if key not in seen:
            seen.add(key)
            violations.append(
                RuleViolation(
                    rule_id=rule_id,
                    opcode=ev.opcode,
                    depth=ev.depth,
                    address=ev.address,
                    detail=detail,
                )
            )

    for i, ev in enumerate(trace):
        op = ev.opcode.upper()

        # OP-011 — forbidden environment opcodes
        if op in _FORBIDDEN_ENV_OPCODES:
            _add("OP-011", ev, f"Forbidden env opcode {op} at depth {ev.depth}")

        # OP-012 — bare GAS (not immediately before a *CALL)
        if op == "GAS":
            next_op = trace[i + 1].opcode.upper() if i + 1 < len(trace) else ""
            if next_op not in _CALL_OPCODES:
                _add("OP-012", ev, f"GAS not followed by CALL (next={next_op or 'END'})")

        # OP-013 — destructive / invalid opcodes
        if op in _FORBIDDEN_DESTRUCTIVE_OPCODES:
            _add("OP-013", ev, f"Forbidden destructive opcode {op}")

        # OP-061 — CALL with non-zero ETH value (except to EntryPoint)
        if op in _VALUE_CALL_OPCODES and ev.value > 0:
            if ev.target.lower() != ep_lc:
                _add(
                    "OP-061",
                    ev,
                    f"CALL with value={ev.value} to {ev.target or '?'} (not EntryPoint)",
                )

        # OP-080 — BALANCE / SELFBALANCE (conservatively flagged; staked entities
        # may use them but we cannot determine stake status from trace alone)
        if op in _BALANCE_OPCODES:
            _add("OP-080", ev, f"{op} used during validation (stake required)")

        # STO-010 / STO-021: storage access in a contract that is not the sender
        # and not the EntryPoint is a cross-contract storage violation.
        if op in _STORAGE_OPCODES:
            addr_lc = ev.address.lower()
            if addr_lc not in (sender_lc, ep_lc, ""):
                rule = "STO-010" if ev.depth <= 1 else "STO-021"
                _add(
                    rule,
                    ev,
                    f"{op} in external contract {ev.address} at depth {ev.depth}"
                    + (f" slot={ev.storage_key}" if ev.storage_key else ""),
                )

    return violations


# ---------------------------------------------------------------------------
# Forge JSON trace parser
# ---------------------------------------------------------------------------


def _parse_forge_trace_json(json_data: Dict[str, Any]) -> List[TraceEvent]:
    """
    Extract a flat list of TraceEvent objects from forge's ``--json -vvvv``
    output.

    Forge's JSON structure (forge test --json -vvvv):
    {
      "<ContractName>:<TestName>": {
        "test_results": {
          "<testFnName>": {
            "decoded_logs": [...],
            "traces": [
              {
                "arena": [
                  {
                    "parent": null,
                    "children": [...],
                    "depth": 0,
                    "steps": [
                      {"op": "PUSH1", "depth": 0, "gas": ..., "gasCost": ..., ...},
                      ...
                    ],
                    "address": "0x..."
                  }
                ]
              }
            ]
          }
        }
      }
    }

    We perform a DFS over the arena nodes, collecting steps from each node and
    tagging them with that node's address (the executing contract).
    """
    events: List[TraceEvent] = []
    idx = 0

    for contract_key, contract_data in json_data.items():
        if not isinstance(contract_data, dict):
            continue
        test_results = contract_data.get("test_results", {})
        for _test_name, test_data in test_results.items():
            if not isinstance(test_data, dict):
                continue
            traces = test_data.get("traces", [])
            for trace_obj in traces:
                if not isinstance(trace_obj, dict):
                    continue
                arena = trace_obj.get("arena", [])
                for node in arena:
                    if not isinstance(node, dict):
                        continue
                    address = str(node.get("address", "")).lower()
                    steps = node.get("steps", [])
                    for step in steps:
                        if not isinstance(step, dict):
                            continue
                        opcode = str(step.get("op", step.get("opcode", "UNKNOWN"))).upper()
                        depth = int(step.get("depth", 0))
                        # For CALL-type ops forge may emit "action" or top-level keys
                        value = int(step.get("value", 0) or 0)
                        target = str(step.get("to", step.get("target", ""))).lower()
                        storage_key = str(step.get("storage_key", step.get("key", ""))).lower()
                        storage_val = str(step.get("storage_value", step.get("val", ""))).lower()
                        gas = int(step.get("gas", 0) or 0)
                        events.append(
                            TraceEvent(
                                opcode=opcode,
                                depth=depth,
                                address=address,
                                value=value,
                                target=target,
                                storage_key=storage_key,
                                storage_value=storage_val,
                                gas=gas,
                                index=idx,
                            )
                        )
                        idx += 1

    return events


# ---------------------------------------------------------------------------
# Harness generator
# ---------------------------------------------------------------------------

_HARNESS_TEMPLATE = """\
// SPDX-License-Identifier: MIT
// AUTO-GENERATED by SpecGuard-AA TraceMonitorBackend (Step F3) — do not edit.
pragma solidity ^0.8.23;

import "forge-std/Test.sol";
import "@account-abstraction/contracts/interfaces/PackedUserOperation.sol";
import "@account-abstraction/contracts/interfaces/IEntryPoint.sol";
import "../../src/worked_examples/{contract_name}.sol";

/// @title  ERC-7562 EVM Trace Scope Test for {contract_name}
/// @notice Exercises validateUserOp through the full EVM so the trace
///         captures every opcode, including those in internal calls.
contract Test_TraceMonitor_{clean_id} is Test {{
    {contract_name} public target;
    address public constant ENTRY_POINT = address(0xEntryPoint1111);
    address public constant SENDER      = address(0xSender222222);

    function setUp() public {{
        target = new {contract_name}(ENTRY_POINT, SENDER);
        // Fund sender so BALANCE checks do not revert
        vm.deal(SENDER, 10 ether);
        vm.deal(address(target), 10 ether);
    }}

    /// @dev  Drive validateUserOp with a minimal op to capture the full trace.
    ///       The test is expected to succeed; violations are detected by the
    ///       Python trace analyser on the recorded opcode stream — not by this
    ///       assertion.
    function testTrace_validationScope() public {{
        PackedUserOperation memory op;
        op.sender = SENDER;
        // Minimal valid callGasLimit / verificationGasLimit in packed form
        op.accountGasLimits = bytes32(
            (uint256(100_000) << 128) | uint256(100_000)
        );
        bytes32 userOpHash = keccak256("specguard-trace-scope");

        // Call as EntryPoint would
        vm.prank(ENTRY_POINT);
        // We call but do NOT assert the return value — the trace is what matters.
        try target.validateUserOp(op, userOpHash, 0) {{}} catch {{}}
    }}
}}
"""


def _generate_harness(
    contract_name: str,
    clean_id: str,
) -> str:
    return _HARNESS_TEMPLATE.format(
        contract_name=contract_name,
        clean_id=clean_id,
    )


# ---------------------------------------------------------------------------
# Backend
# ---------------------------------------------------------------------------


def _find_forge() -> Optional[str]:
    """Return the forge binary path, or None if Foundry is not installed."""
    return shutil.which("forge")


class TraceMonitorBackend(ValidationBackend):
    """
    EVM Trace Monitor Backend (Step F3).

    Generates a minimal Foundry harness that invokes ``validateUserOp``,
    executes it with ``forge test --json -vvvv``, parses the structured opcode
    trace from the JSON output, and evaluates every compiled ERC-7562 O_Sigma
    rule against the trace.  Violations are reported by their normative rule
    identifier (e.g. ``OP-011``).
    """

    BACKEND_NAME = "TraceMonitor"

    def __init__(
        self,
        forge_path: Optional[str] = None,
        test_dir: str = "contracts/test/generated",
        artifact_dir: str = "contracts/test/artifacts",
        sender_address: str = "0xSender222222",
        entry_point_address: str = "0xEntryPoint1111",
        timeout: int = 60,
    ) -> None:
        self.test_dir = test_dir
        self.artifact_dir = artifact_dir
        self.sender_address = sender_address
        self.entry_point_address = entry_point_address
        self.timeout = timeout
        os.makedirs(self.test_dir, exist_ok=True)
        os.makedirs(self.artifact_dir, exist_ok=True)
        self.forge_path: Optional[str] = forge_path if forge_path is not None else _find_forge()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def validate(
        self,
        property: Property,
        binding: PropertyBinding,
        facts: ContractFacts,
    ) -> ValidationResult:
        """
        Evaluate ERC-7562 scope rules against an instrumented EVM trace.

        Only processes SCOPE-type properties; all others return HELD immediately.
        """
        if property.template_type != PropertyType.SCOPE:
            return ValidationResult(
                outcome=Outcome.HELD,
                backend=self.BACKEND_NAME,
                property_id=property.property_id,
            )

        clean_id = re.sub(r"[^a-zA-Z0-9_]", "_", property.property_id)
        artifact_prop_dir = os.path.join(self.artifact_dir, clean_id)
        os.makedirs(artifact_prop_dir, exist_ok=True)
        raw_log_path = os.path.join(artifact_prop_dir, "trace_run.log")

        # Graceful degradation: forge not installed → HARNESS_ERROR
        if not self.forge_path:
            return ValidationResult(
                outcome=Outcome.HARNESS_ERROR,
                backend=self.BACKEND_NAME,
                property_id=property.property_id,
                error_message=(
                    "'forge' binary not found on PATH. "
                    "Install Foundry: curl -L https://foundry.paradigm.xyz | bash && foundryup"
                ),
                raw_artifact_path=raw_log_path,
            )

        contract_name = facts.contract_name
        harness_code = _generate_harness(contract_name, clean_id)
        contract_test_name = f"Test_TraceMonitor_{clean_id}"
        test_file_path = os.path.join(self.test_dir, f"{contract_test_name}.t.sol")

        with open(test_file_path, "w", encoding="utf-8") as f:
            f.write(harness_code)

        # forge test --json -vvvv  (structured JSON + full trace output)
        cmd = [
            self.forge_path,
            "test",
            "--match-contract", contract_test_name,
            "--json",
            "-vvvv",
        ]

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                encoding="utf-8",
                errors="replace",
                cwd=os.path.abspath("."),
                env=os.environ.copy(),
                timeout=self.timeout,
            )
            raw_output = (result.stdout or "") + "\n" + (result.stderr or "")
            with open(raw_log_path, "w", encoding="utf-8") as f:
                f.write(raw_output)

            return self._evaluate(
                stdout=result.stdout or "",
                returncode=result.returncode,
                harness_code=harness_code,
                property_id=property.property_id,
                raw_log_path=raw_log_path,
            )

        except subprocess.TimeoutExpired:
            with open(raw_log_path, "w", encoding="utf-8") as f:
                f.write("TIMEOUT: forge test exceeded time limit\n")
            return ValidationResult(
                outcome=Outcome.TIMEOUT,
                backend=self.BACKEND_NAME,
                property_id=property.property_id,
                error_message=f"Execution timed out after {self.timeout}s",
                raw_artifact_path=raw_log_path,
            )
        except Exception as exc:
            with open(raw_log_path, "w", encoding="utf-8") as f:
                f.write(f"HARNESS_ERROR: {exc}\n")
            return ValidationResult(
                outcome=Outcome.HARNESS_ERROR,
                backend=self.BACKEND_NAME,
                property_id=property.property_id,
                error_message=f"Harness execution error: {exc}",
                raw_artifact_path=raw_log_path,
            )

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _evaluate(
        self,
        stdout: str,
        returncode: int,
        harness_code: str,
        property_id: str,
        raw_log_path: str,
    ) -> ValidationResult:
        """
        Parse forge JSON output, extract trace, run rule evaluation, and
        convert the result into a ValidationResult.

        Rule B: decisions are made on structured JSON data only — no substring
        matching on console output.
        """
        json_data = self._extract_json(stdout)
        if json_data is None:
            return ValidationResult(
                outcome=Outcome.HARNESS_ERROR,
                backend=self.BACKEND_NAME,
                property_id=property_id,
                error_message=(
                    f"Harness compilation or execution failed "
                    f"(exit code {returncode}) — no JSON output"
                ),
                raw_artifact_path=raw_log_path,
            )

        # Check for harness-level setUp / compile failures via JSON structure
        for _key, contract_data in json_data.items():
            if not isinstance(contract_data, dict):
                continue
            if contract_data.get("error"):
                return ValidationResult(
                    outcome=Outcome.HARNESS_ERROR,
                    backend=self.BACKEND_NAME,
                    property_id=property_id,
                    error_message=f"Harness setUp/compile error: {contract_data['error']}",
                    raw_artifact_path=raw_log_path,
                )

        # Extract trace and evaluate O_Sigma rules
        trace = _parse_forge_trace_json(json_data)
        violations = evaluate_rules(
            trace,
            sender=self.sender_address,
            entry_point=self.entry_point_address,
        )

        if violations:
            first = violations[0]
            # Build structured trace_events list (rule_id: detail)
            trace_event_strs = [
                f"{v.rule_id}: {v.opcode} at depth={v.depth} in {v.address}"
                + (f" — {v.detail}" if v.detail else "")
                for v in violations
            ]
            witness = Witness(
                backend=self.BACKEND_NAME,
                reproducible_test_code=harness_code,
                user_op_json={
                    "violated_rules": [v.rule_id for v in violations],
                    "violation_count": len(violations),
                },
                trace_events=trace_event_strs,
                is_valid=True,
            )
            return ValidationResult(
                outcome=Outcome.VIOLATED,
                backend=self.BACKEND_NAME,
                property_id=property_id,
                failing_obligation_id=first.rule_id,
                witness=witness,
                error_message=(
                    f"ERC-7562 rule violation(s): "
                    + ", ".join(dict.fromkeys(v.rule_id for v in violations))
                ),
                raw_artifact_path=raw_log_path,
            )

        return ValidationResult(
            outcome=Outcome.HELD,
            backend=self.BACKEND_NAME,
            property_id=property_id,
            raw_artifact_path=raw_log_path,
        )

    @staticmethod
    def _extract_json(stdout: str) -> Optional[Dict[str, Any]]:
        """Extract JSON payload from forge output, skipping any warnings."""
        if not stdout:
            return None
        start = stdout.find("{")
        end = stdout.rfind("}")
        if start != -1 and end != -1 and end > start:
            try:
                return json.loads(stdout[start : end + 1])
            except Exception:
                pass
        return None

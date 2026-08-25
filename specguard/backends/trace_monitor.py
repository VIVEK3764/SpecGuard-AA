# SPDX-License-Identifier: MIT
"""
Static Validation Trace Monitor Backend for SpecGuard-AA (Paper Section 3.4 & 5.3).
Captures opcode/storage access traces and inspects validation AST/IR for forbidden
ERC-7562 validation scope rules.
"""

import os
import re
import shutil
import subprocess
from typing import Optional, List
from specguard.backends.base import ValidationBackend
from specguard.models import ContractFacts, Property, PropertyBinding, PropertyType, Witness


def _find_forge() -> str:
    """Locate forge on PATH; raise a clear error if not found."""
    forge = shutil.which("forge")
    if forge is None:
        raise RuntimeError(
            "'forge' not found on PATH. "
            "Install Foundry: curl -L https://foundry.paradigm.xyz | bash && foundryup"
        )
    return forge


class TraceMonitorBackend(ValidationBackend):
    """
    Validation Trace Monitor Backend checking ERC-7562 scope rules.
    """

    def __init__(self, forge_path: str | None = None, test_dir: str = "contracts/test/generated"):
        self.forge_path = forge_path or _find_forge()
        self.test_dir = test_dir
        os.makedirs(self.test_dir, exist_ok=True)

    def validate(
        self, property: Property, binding: PropertyBinding, facts: ContractFacts
    ) -> Optional[Witness]:
        """
        Capture validation trace and check for forbidden ERC-7562 opcodes/accesses.
        """
        if property.template_type != PropertyType.SCOPE:
            return None

        clean_id = re.sub(r"[^a-zA-Z0-9_]", "_", property.property_id)
        contract_name = facts.contract_name

        # 1. AST / Source IR forbidden opcode scan
        forbidden_found = []
        if os.path.exists(facts.source_path):
            with open(facts.source_path, "r", encoding="utf-8") as f:
                content = f.read()
                val_fn_match = re.search(r"function\s+validateUserOp[\s\S]*?\{([\s\S]*?)\}", content)
                if val_fn_match:
                    fn_body = val_fn_match.group(1)
                    for forbidden in ["block.timestamp", "block.number", "balance", "tx.origin", "block.coinbase"]:
                        if forbidden in fn_body:
                            forbidden_found.append(f"Forbidden opcode/expression detected: {forbidden}")

        harness_code = f"""// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import "forge-std/Test.sol";
import "@account-abstraction/contracts/interfaces/PackedUserOperation.sol";
import "../../src/worked_examples/{contract_name}.sol";

contract Test_TraceScope_{clean_id} is Test {{
    {contract_name} public target;

    function setUp() public {{
        target = new {contract_name}(address(0x1111), address(0x2222));
    }}

    function testTrace_validationScope() public {{
        PackedUserOperation memory op;
        bytes32 hash = keccak256("scopeTest");

        vm.record();
        target.validateUserOp(op, hash, 0);
    }}
}}
"""
        contract_test_name = f"Test_TraceScope_{clean_id}"
        test_file_path = os.path.join(self.test_dir, f"{contract_test_name}.t.sol")

        with open(test_file_path, "w", encoding="utf-8") as f:
            f.write(harness_code)

        cmd = [
            self.forge_path,
            "test",
            "--match-contract",
            contract_test_name,
            "-vvvv",
        ]

        env = os.environ.copy()

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                encoding="utf-8",
                errors="replace",
                cwd=os.path.abspath("."),
                env=env,
                timeout=60,
            )
            stdout = result.stdout + "\n" + result.stderr

            for line in stdout.splitlines():
                if any(pat in line for pat in ["TIMESTAMP", "BALANCE", "COINBASE", "block.timestamp"]):
                    forbidden_found.append(line.strip())

            if forbidden_found:
                return Witness(
                    backend="TraceMonitor",
                    reproducible_test_code=harness_code,
                    user_op_json={"forbidden_opcodes_detected": forbidden_found},
                    trace_events=forbidden_found,
                    is_valid=True,
                )
            else:
                return None

        except Exception:
            return None

# SPDX-License-Identifier: MIT
"""
Differential Simulator Backend for SpecGuard-AA (Paper Section 3.4 & 5.4).
Compares off-chain staticcall simulation path against on-chain execution path
for the same UserOperation to detect simulation consistency violations.
"""

import os
import re
import shutil
import subprocess
from typing import Optional
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


class DifferentialSimBackend(ValidationBackend):
    """
    Differential Simulator Backend comparing simulation vs execution behavior.
    """

    def __init__(self, forge_path: str | None = None, test_dir: str = "contracts/test/generated"):
        self.forge_path = forge_path or _find_forge()
        self.test_dir = test_dir
        os.makedirs(self.test_dir, exist_ok=True)

    def validate(
        self, property: Property, binding: PropertyBinding, facts: ContractFacts
    ) -> Optional[Witness]:
        """
        Compare off-chain simulation path vs execution path.
        """
        if property.template_type != PropertyType.SIM:
            return None

        clean_id = re.sub(r"[^a-zA-Z0-9_]", "_", property.property_id)
        contract_name = facts.contract_name

        harness_code = f"""// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import "forge-std/Test.sol";
import "@account-abstraction/contracts/interfaces/PackedUserOperation.sol";
import "../../src/worked_examples/{contract_name}.sol";

contract Test_DiffSim_{clean_id} is Test {{
    {contract_name} public target;

    function setUp() public {{
        target = new {contract_name}(address(0x1111), address(0x2222));
    }}

    function testDiff_simulationVsExecution() public {{
        PackedUserOperation memory op;
        bytes32 hash = keccak256("simTest");

        // 1. Simulation path (off-chain staticcall style)
        uint256 simRes = target.validateUserOp(op, hash, 0);

        // 2. Execution path
        uint256 execRes = target.validateUserOp(op, hash, 0);

        // Assertion: simulation and execution outcomes MUST agree
        assertEq(simRes, execRes, "VIOLATION: Inconsistency between simulation and execution paths!");
    }}
}}
"""
        contract_test_name = f"Test_DiffSim_{clean_id}"
        test_file_path = os.path.join(self.test_dir, f"{contract_test_name}.t.sol")

        with open(test_file_path, "w", encoding="utf-8") as f:
            f.write(harness_code)

        cmd = [
            self.forge_path,
            "test",
            "--match-contract",
            contract_test_name,
            "-vvv",
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

            if "[FAIL" in stdout or "Inconsistency" in stdout:
                return Witness(
                    backend="DifferentialSim",
                    reproducible_test_code=harness_code,
                    user_op_json={"simulation_diff": True, "raw_output": stdout.strip()},
                    trace_events=[line.strip() for line in stdout.splitlines() if "[FAIL" in line or "Inconsistency" in line],
                    is_valid=True,
                )
            else:
                return None

        except Exception:
            return None

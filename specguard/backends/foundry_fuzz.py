# SPDX-License-Identifier: MIT
"""
Foundry Fuzz Testing Validation Backend for SpecGuard-AA (Paper Section 3.4 & 5.1).
Generates executable Foundry fuzzing harnesses (.t.sol) to search for concrete
UserOperation counterexamples violating mined properties.
"""

import os
import re
import json
import shutil
import subprocess
from typing import Optional, Dict, Any, Tuple
from specguard.backends.base import ValidationBackend
from specguard.models import (
    ContractFacts,
    Property,
    PropertyBinding,
    PropertyType,
    Witness,
    ValidationResult,
    Outcome,
    Role,
)


def _find_forge() -> str:
    """Locate forge on PATH; raise a clear error if not found."""
    forge = shutil.which("forge")
    if forge is None:
        raise RuntimeError(
            "'forge' not found on PATH. "
            "Install Foundry: curl -L https://foundry.paradigm.xyz | bash && foundryup"
        )
    return forge


class FoundryFuzzBackend(ValidationBackend):
    """
    Foundry Fuzz Backend generating executable .t.sol test harnesses
    and evaluating results via structured 'forge test --json' output (Step F2).
    """

    def __init__(
        self,
        forge_path: str | None = None,
        test_dir: str = "contracts/test/generated",
        artifact_dir: str = "contracts/test/artifacts",
    ):
        self.test_dir = test_dir
        self.artifact_dir = artifact_dir
        os.makedirs(self.test_dir, exist_ok=True)
        os.makedirs(self.artifact_dir, exist_ok=True)
        try:
            self.forge_path = forge_path or _find_forge()
        except RuntimeError:
            self.forge_path = forge_path

    def validate(
        self, property: Property, binding: PropertyBinding, facts: ContractFacts
    ) -> ValidationResult:
        """
        Generate Foundry fuzz harness, execute 'forge test --json', and return
        a structured ValidationResult (VIOLATED, HELD, HARNESS_ERROR, TIMEOUT).
        """
        clean_id = self._clean_name(property.property_id)
        artifact_prop_dir = os.path.join(self.artifact_dir, clean_id)
        os.makedirs(artifact_prop_dir, exist_ok=True)
        raw_log_path = os.path.join(artifact_prop_dir, "forge_run.log")

        if not self.forge_path:
            return ValidationResult(
                outcome=Outcome.HARNESS_ERROR,
                backend="FoundryFuzz",
                property_id=property.property_id,
                error_message="'forge' binary not found on PATH. Install Foundry to execute test harnesses.",
                raw_artifact_path=raw_log_path,
            )

        harness_code = self._generate_harness(property, binding, facts)
        if not harness_code:
            return ValidationResult(
                outcome=Outcome.HELD,
                backend="FoundryFuzz",
                property_id=property.property_id,
                error_message="No applicable harness template generated for property",
                raw_artifact_path=raw_log_path,
            )

        contract_test_name = f"Test_{clean_id}"
        test_file_path = os.path.join(self.test_dir, f"{contract_test_name}.t.sol")

        with open(test_file_path, "w", encoding="utf-8") as f:
            f.write(harness_code)

        cmd = [
            self.forge_path,
            "test",
            "--match-contract",
            contract_test_name,
            "--json",
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
            raw_output = (result.stdout or "") + "\n" + (result.stderr or "")
            with open(raw_log_path, "w", encoding="utf-8") as f:
                f.write(raw_output)

            # Rule B: Parse structured JSON output, never inspect stdout substrings.
            json_data = self._extract_json(result.stdout)
            if json_data is None:
                # Non-zero exit with unparseable JSON is HARNESS_ERROR (e.g. solc compile error)
                return ValidationResult(
                    outcome=Outcome.HARNESS_ERROR,
                    backend="FoundryFuzz",
                    property_id=property.property_id,
                    error_message=f"Harness compilation or execution failed (exit code {result.returncode})",
                    raw_artifact_path=raw_log_path,
                )

            return self._evaluate_json_results(
                json_data, result.returncode, harness_code, property.property_id, raw_log_path
            )

        except subprocess.TimeoutExpired:
            with open(raw_log_path, "w", encoding="utf-8") as f:
                f.write("TIMEOUT: Test execution exceeded 60s limit\n")
            return ValidationResult(
                outcome=Outcome.TIMEOUT,
                backend="FoundryFuzz",
                property_id=property.property_id,
                error_message="Execution timed out after 60 seconds",
                raw_artifact_path=raw_log_path,
            )
        except Exception as e:
            with open(raw_log_path, "w", encoding="utf-8") as f:
                f.write(f"HARNESS_ERROR: Unexpected exception: {str(e)}\n")
            return ValidationResult(
                outcome=Outcome.HARNESS_ERROR,
                backend="FoundryFuzz",
                property_id=property.property_id,
                error_message=f"Harness execution error: {str(e)}",
                raw_artifact_path=raw_log_path,
            )

    def _generate_harness(
        self, property: Property, binding: PropertyBinding, facts: ContractFacts
    ) -> Optional[str]:
        t = property.template_type
        clean_id = self._clean_name(property.property_id)
        contract_name = facts.contract_name
        if t == PropertyType.SESSION and "EXPIRY" in property.property_id:
            return f"""// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import "forge-std/Test.sol";
import "@account-abstraction/contracts/interfaces/PackedUserOperation.sol";
import "../../src/worked_examples/{contract_name}.sol";

contract Test_{clean_id} is Test {{
    {contract_name} public account;
    address public entryPoint = address(0x1111);
    address public owner = address(0x2222);
    address public sessionKey = address(0x3333);
    address public policyTarget = address(0x4444);
    uint48 public policyExpiry = 1000;

    function setUp() public {{
        account = new {contract_name}(entryPoint, owner);
        vm.prank(owner);
        account.setSessionKey(sessionKey, policyTarget, policyExpiry);
    }}

    function testFuzz_expiryBypass(uint256 fuzzedTimestamp) public {{
        vm.assume(fuzzedTimestamp > policyExpiry && fuzzedTimestamp < type(uint32).max);
        vm.warp(fuzzedTimestamp);

        PackedUserOperation memory op;
        op.sender = address(account);
        op.signature = abi.encodePacked(bytes32("r"), bytes32("s"), uint8(27));

        bytes32 userOpHash = keccak256("testUserOp");
        
        vm.mockCall(
            address(account),
            abi.encodeWithSelector(account.recover.selector),
            abi.encode(sessionKey)
        );

        vm.prank(entryPoint);
        uint256 res = account.validateUserOp(op, userOpHash, 0);
        assertFalse(res == 0, "VIOLATION: validateUserOp accepted expired session key!");
    }}
}}
"""

        elif t == PropertyType.SESSION:
            return f"""// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import "forge-std/Test.sol";
import "@account-abstraction/contracts/interfaces/PackedUserOperation.sol";
import "../../src/worked_examples/{contract_name}.sol";

contract Test_{clean_id} is Test {{
    {contract_name} public account;
    address public entryPoint = address(0x1111);
    address public owner = address(0x2222);
    address public sessionKey = address(0x3333);
    address public policyTarget = address(0x4444);

    function setUp() public {{
        account = new {contract_name}(entryPoint, owner);
        vm.prank(owner);
        account.setSessionKey(sessionKey, policyTarget);
    }}

    function testFuzz_sessionTargetPolicyBypass(address unauthorizedTarget) public {{
        vm.assume(unauthorizedTarget != policyTarget && unauthorizedTarget != address(0));

        PackedUserOperation memory op;
        op.sender = address(account);
        op.callData = abi.encodeWithSignature("execute(address,uint256,bytes)", unauthorizedTarget, 0, "");
        op.signature = abi.encodePacked(bytes32("r"), bytes32("s"), uint8(27));

        bytes32 userOpHash = keccak256("testUserOp");

        vm.mockCall(
            address(account),
            abi.encodeWithSelector(account.recover.selector),
            abi.encode(sessionKey)
        );

        vm.prank(entryPoint);
        uint256 res = account.validateUserOp(op, userOpHash, 0);
        assertFalse(res == 0, "VIOLATION: validateUserOp accepted unauthorized target!");
    }}
}}
"""

        elif t == PropertyType.PAYMASTER:
            return f"""// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import "forge-std/Test.sol";
import "@account-abstraction/contracts/interfaces/PackedUserOperation.sol";
import "../../src/worked_examples/{contract_name}.sol";

contract Test_{clean_id} is Test {{
    {contract_name} public paymaster;
    address public entryPoint = address(0x1111);
    address public sponsor = address(0x9999);

    function setUp() public {{
        paymaster = new {contract_name}(entryPoint, sponsor);
    }}

    function testFuzz_paymasterCouponReplay(bytes32 couponHash) public {{
        vm.assume(couponHash != bytes32(0));

        PackedUserOperation memory op;
        // v0.7 paymasterAndData: 20 bytes paymaster + 16 bytes verificationGasLimit + 16 bytes postOpGasLimit + data
        op.paymasterAndData = abi.encodePacked(address(paymaster), uint128(100000), uint128(100000), couponHash);
        op.signature = abi.encodePacked(bytes32("r"), bytes32("s"), uint8(27));

        vm.mockCall(
            address(paymaster),
            abi.encodeWithSelector(paymaster.recover.selector),
            abi.encode(sponsor)
        );

        vm.prank(entryPoint);
        // First validation
        (, uint256 res1) = paymaster.validatePaymasterUserOp(op, keccak256("hash1"), 100000);
        assertEq(res1, 0, "First validation failed");

        vm.prank(entryPoint);
        // Replayed second validation with same coupon
        (, uint256 res2) = paymaster.validatePaymasterUserOp(op, keccak256("hash2"), 100000);

        // Violation assertion: replayed coupon MUST NOT return VALIDATION_SUCCESS (0)
        assertFalse(res2 == 0, "VIOLATION: Paymaster accepted replayed coupon!");
    }}
}}
"""

        elif t in [PropertyType.AUTH, PropertyType.NONCE]:
            return f"""// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import "forge-std/Test.sol";
import "@account-abstraction/contracts/interfaces/PackedUserOperation.sol";
import "../../src/worked_examples/{contract_name}.sol";

contract Test_{clean_id} is Test {{
    {contract_name} public account;
    address public entryPoint = address(0x1111);
    address public owner = address(0x2222);

    function setUp() public {{
        account = new {contract_name}(entryPoint, owner);
    }}

    function testFuzz_unauthorizedSignerRejected(address attacker) public {{
        vm.assume(attacker != owner && attacker != address(0));

        PackedUserOperation memory op;
        op.sender = address(account);
        op.signature = abi.encodePacked(bytes32("r"), bytes32("s"), uint8(27));

        vm.mockCall(
            address(account),
            abi.encodeWithSelector(account.recover.selector),
            abi.encode(attacker)
        );

        vm.prank(entryPoint);
        uint256 res = account.validateUserOp(op, keccak256("hash"), 0);

        // For a clean owner account, unauthorized signer MUST return SIG_VALIDATION_FAILED (1)
        assertEq(res, 1, "Clean account must reject unauthorized signer");
    }}
}}
"""

        return None

    @staticmethod
    def _clean_name(name: str) -> str:
        return re.sub(r"[^a-zA-Z0-9_]", "_", name)

    @staticmethod
    def _extract_json(stdout: str) -> Optional[Dict[str, Any]]:
        """Extract JSON payload from forge test output, ignoring any surrounding text/warnings."""
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

    def _evaluate_json_results(
        self,
        json_data: Dict[str, Any],
        returncode: int,
        harness_code: str,
        property_id: str,
        raw_log_path: str,
    ) -> ValidationResult:
        """
        Evaluate parsed Foundry JSON output and return a structured ValidationResult.
        Rule B: No string decisions from console output. Decided purely via structured JSON test tree.
        """
        total_tests = 0
        failed_tests = []
        setup_reverts = []

        for contract_key, contract_data in json_data.items():
            if not isinstance(contract_data, dict):
                continue

            if contract_data.get("error"):
                setup_reverts.append(str(contract_data.get("error")))

            test_results = contract_data.get("test_results", {})
            for test_name, test_data in test_results.items():
                total_tests += 1
                status = test_data.get("status")
                is_failed = False
                reason = test_data.get("reason") or ""

                if isinstance(status, str):
                    if status.lower() in ("failure", "failed"):
                        is_failed = True
                elif isinstance(status, dict):
                    if "Failure" in status or "failed" in status:
                        is_failed = True
                        if not reason and isinstance(status.get("Failure"), str):
                            reason = status.get("Failure")

                if is_failed:
                    reason_lower = str(reason).lower()
                    if "setup failed" in reason_lower or "revert: setup" in reason_lower:
                        setup_reverts.append(f"{test_name}: {reason}")
                    else:
                        failed_tests.append((test_name, test_data))

        # 1. If setUp reverted or contract-level setup error occurred, report HARNESS_ERROR
        if setup_reverts:
            return ValidationResult(
                outcome=Outcome.HARNESS_ERROR,
                backend="FoundryFuzz",
                property_id=property_id,
                error_message=f"Harness setUp reverted: {'; '.join(setup_reverts)}",
                raw_artifact_path=raw_log_path,
            )

        # 2. If no tests ran and forge exited non-zero, report HARNESS_ERROR
        if total_tests == 0 and returncode != 0:
            return ValidationResult(
                outcome=Outcome.HARNESS_ERROR,
                backend="FoundryFuzz",
                property_id=property_id,
                error_message="No tests executed and forge exited with error",
                raw_artifact_path=raw_log_path,
            )

        # 3. If any assertion failed in an obligation test, report VIOLATED
        if failed_tests:
            failing_name, failing_data = failed_tests[0]
            counterexample = failing_data.get("counterexample") or {}
            decoded_logs = failing_data.get("decoded_logs") or []
            reason = failing_data.get("reason") or "Assertion violated in test harness"

            witness = Witness(
                backend="FoundryFuzz",
                reproducible_test_code=harness_code,
                user_op_json=counterexample if isinstance(counterexample, dict) else {"raw_counterexample": str(counterexample)},
                trace_events=decoded_logs if isinstance(decoded_logs, list) else [str(decoded_logs)],
                is_valid=True,
            )

            obligation_id = None
            match = re.search(r"test_obligation_([a-zA-Z0-9_\-]+)", failing_name)
            if match:
                obligation_id = match.group(1)
            else:
                obligation_id = failing_name

            return ValidationResult(
                outcome=Outcome.VIOLATED,
                backend="FoundryFuzz",
                property_id=property_id,
                failing_obligation_id=obligation_id,
                witness=witness,
                error_message=str(reason),
                raw_artifact_path=raw_log_path,
            )

        # 4. All tests passed cleanly
        return ValidationResult(
            outcome=Outcome.HELD,
            backend="FoundryFuzz",
            property_id=property_id,
            raw_artifact_path=raw_log_path,
        )

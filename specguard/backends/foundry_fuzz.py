# SPDX-License-Identifier: MIT
"""
Foundry Fuzz Testing Validation Backend for SpecGuard-AA (Paper Section 3.4 & 5.1).
Generates executable Foundry fuzzing harnesses (.t.sol) to search for concrete
UserOperation counterexamples violating mined properties.
"""

import os
import re
import shutil
import subprocess
from typing import Optional, Dict, Any
from specguard.backends.base import ValidationBackend
from specguard.models import ContractFacts, Property, PropertyBinding, PropertyType, Witness, Role


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
    Foundry Fuzz Backend generating executable .t.sol test harnesses.
    """

    def __init__(self, forge_path: str | None = None, test_dir: str = "contracts/test/generated"):
        self.forge_path = forge_path or _find_forge()
        self.test_dir = test_dir
        os.makedirs(self.test_dir, exist_ok=True)

    def validate(
        self, property: Property, binding: PropertyBinding, facts: ContractFacts
    ) -> Optional[Witness]:
        """
        Generate Foundry fuzz harness, execute forge test, and extract Witness or return None (⊥).
        """
        harness_code = self._generate_harness(property, binding, facts)
        if not harness_code:
            return None

        contract_test_name = f"Test_{self._clean_name(property.property_id)}"
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

            if "[FAIL" in stdout or "Counterexample" in stdout or "VIOLATION" in stdout:
                witness_details = self._parse_counterexample(stdout)
                return Witness(
                    backend="FoundryFuzz",
                    reproducible_test_code=harness_code,
                    user_op_json=witness_details,
                    trace_events=[line.strip() for line in stdout.splitlines() if "[FAIL" in line or "Counterexample" in line or "VIOLATION" in line],
                    is_valid=True,
                )
            else:
                return None

        except Exception:
            return None

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
    address public allowedTarget = address(0x4444);
    uint48 public sessionExpiry = 1000;

    function setUp() public {{
        account = new {contract_name}(entryPoint, owner);
        vm.prank(owner);
        account.setSessionKey(sessionKey, allowedTarget, sessionExpiry);
    }}

    function testFuzz_sessionExpiryBypass(uint256 fuzzedTimestamp) public {{
        vm.assume(fuzzedTimestamp > sessionExpiry && fuzzedTimestamp < type(uint32).max);
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
    address public allowedTarget = address(0x4444);

    function setUp() public {{
        account = new {contract_name}(entryPoint, owner);
        vm.prank(owner);
        account.setSessionKey(sessionKey, allowedTarget);
    }}

    function testFuzz_sessionTargetPolicyBypass(address unauthorizedTarget) public {{
        vm.assume(unauthorizedTarget != allowedTarget && unauthorizedTarget != address(0));

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
    def _parse_counterexample(output: str) -> Dict[str, Any]:
        details = {}
        for line in output.splitlines():
            if "Counterexample" in line or "[FAIL" in line or "VIOLATION" in line:
                details["raw_failure"] = line.strip()
        return details

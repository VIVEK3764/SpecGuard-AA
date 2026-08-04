// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import "../../src/worked_examples/SessionAccount.sol";

contract Test_PROP_SESSION_TARGET_5259 is Test {
    SessionAccount public account;
    address public owner = address(0x1111);
    address public sessionKey = address(0x2222);
    address public allowedTarget = address(0x3333);

    function setUp() public {
        account = new SessionAccount(owner);
        account.setSessionKey(sessionKey, allowedTarget);
    }

    function testFuzz_sessionTargetPolicyBypass(address unauthorizedTarget) public {
        vm.assume(unauthorizedTarget != allowedTarget && unauthorizedTarget != address(0));

        UserOp memory op;
        op.sender = address(account);
        op.callData = abi.encodeWithSignature("execute(address,bytes)", unauthorizedTarget, "");
        op.signature = abi.encodePacked(bytes32("r"), bytes32("s"), uint8(27));

        bytes32 userOpHash = keccak256("testUserOp");

        vm.mockCall(
            address(account),
            abi.encodeWithSelector(account.recover.selector),
            abi.encode(sessionKey)
        );

        uint256 res = account.validateUserOp(op, userOpHash);
        assertFalse(res == 0, "VIOLATION: validateUserOp accepted unauthorized target!");
    }
}

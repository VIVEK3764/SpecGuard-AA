// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import "../../src/worked_examples/ExpirySessionAccount.sol";

contract Test_PROP_SESSION_EXPIRY_3811 is Test {
    ExpirySessionAccount public account;
    address public owner = address(0x1111);
    address public sessionKey = address(0x2222);
    address public allowedTarget = address(0x3333);
    uint256 public sessionExpiry = 1000;

    function setUp() public {
        account = new ExpirySessionAccount(owner);
        account.setSessionKey(sessionKey, allowedTarget, sessionExpiry);
    }

    function testFuzz_sessionExpiryBypass(uint256 fuzzedTimestamp) public {
        vm.assume(fuzzedTimestamp > sessionExpiry);
        vm.warp(fuzzedTimestamp);

        UserOp memory op;
        op.sender = address(account);
        op.signature = abi.encodePacked(bytes32("r"), bytes32("s"), uint8(27));

        bytes32 userOpHash = keccak256("testUserOp");
        
        vm.mockCall(
            address(account),
            abi.encodeWithSelector(account.recover.selector),
            abi.encode(sessionKey)
        );

        uint256 res = account.validateUserOp(op, userOpHash);
        assertFalse(res == 0, "VIOLATION: validateUserOp accepted expired session key!");
    }
}

// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import "../../src/worked_examples/SimpleOwnerAccount.sol";

contract Test_PROP_NONCE_2860 is Test {
    SimpleOwnerAccount public account;
    address public owner = address(0x1111);

    function setUp() public {
        account = new SimpleOwnerAccount(owner);
    }

    function testFuzz_unauthorizedSignerRejected(address attacker) public {
        vm.assume(attacker != owner && attacker != address(0));

        UserOp memory op;
        op.sender = address(account);
        op.signature = abi.encodePacked(bytes32("r"), bytes32("s"), uint8(27));

        vm.mockCall(
            address(account),
            abi.encodeWithSelector(account.recover.selector),
            abi.encode(attacker)
        );

        uint256 res = account.validateUserOp(op, keccak256("hash"));

        // For a clean owner account, unauthorized signer MUST return SIG_VALIDATION_FAILED (1)
        assertEq(res, 1, "Clean account properly rejected unauthorized signer");
    }
}

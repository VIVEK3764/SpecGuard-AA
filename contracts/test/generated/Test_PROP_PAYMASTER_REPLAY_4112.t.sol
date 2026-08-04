// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import "../../src/worked_examples/CouponPaymaster.sol";

contract Test_PROP_PAYMASTER_REPLAY_4112 is Test {
    CouponPaymaster public paymaster;
    address public sponsor = address(0x9999);

    function setUp() public {
        paymaster = new CouponPaymaster(sponsor);
    }

    function testFuzz_paymasterCouponReplay(bytes32 couponHash) public {
        vm.assume(couponHash != bytes32(0));

        UserOp memory op;
        op.paymasterAndData = abi.encodePacked(couponHash);
        op.signature = abi.encodePacked(bytes32("r"), bytes32("s"), uint8(27));

        vm.mockCall(
            address(paymaster),
            abi.encodeWithSelector(paymaster.recover.selector),
            abi.encode(sponsor)
        );

        // First validation
        (, uint256 res1) = paymaster.validatePaymasterUserOp(op, keccak256("hash1"), 100000);
        assertEq(res1, 0, "First validation failed");

        // Replayed second validation with same coupon
        (, uint256 res2) = paymaster.validatePaymasterUserOp(op, keccak256("hash2"), 100000);

        // Violation assertion: replayed coupon MUST NOT return VALIDATION_SUCCESS (0)
        assertFalse(res2 == 0, "VIOLATION: Paymaster accepted replayed coupon!");
    }
}

// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import "../../src/worked_examples/ScopeAccountViolating.sol";

contract Test_TraceScope_PROP_SCOPE_001 is Test {
    ScopeAccountViolating public target;

    function setUp() public {
        target = new ScopeAccountViolating(address(0x1111));
    }

    function testTrace_validationScope() public {
        UserOp memory op;
        bytes32 hash = keccak256("scopeTest");

        vm.record();
        target.validateUserOp(op, hash);
    }
}

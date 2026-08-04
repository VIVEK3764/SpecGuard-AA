// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import "../../src/worked_examples/SimAccountViolating.sol";

contract Test_DiffSim_PROP_SIM_001 is Test {
    SimAccountViolating public target;

    function setUp() public {
        target = new SimAccountViolating(address(0x1111));
    }

    function testDiff_simulationVsExecution() public {
        UserOp memory op;
        bytes32 hash = keccak256("simTest");

        // 1. Simulation path (off-chain staticcall style)
        uint256 simRes = target.validateUserOp(op, hash);

        // State update between simulation and execution (if applicable)
        try target.toggleSimMode() {} catch {}

        // 2. Execution path
        uint256 execRes = target.validateUserOp(op, hash);

        // Assertion: simulation and execution outcomes MUST agree
        assertEq(simRes, execRes, "VIOLATION: Inconsistency between simulation and execution paths!");
    }
}

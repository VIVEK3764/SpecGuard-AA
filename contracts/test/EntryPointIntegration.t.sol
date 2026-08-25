// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import "forge-std/Test.sol";
import "@account-abstraction/contracts/core/EntryPoint.sol";
import "@account-abstraction/contracts/interfaces/PackedUserOperation.sol";
import "../src/worked_examples/SimpleOwnerAccount.sol";

/// @title DummyTarget
contract DummyTarget {
    uint256 public value;
    function setVal(uint256 _val) external {
        value = _val;
    }
}

/// @title EntryPointIntegrationTest
/// @notice Step A2 verification test: Submits a real PackedUserOperation through EntryPoint.handleOps()
contract EntryPointIntegrationTest is Test {
    EntryPoint public entryPoint;
    SimpleOwnerAccount public account;
    DummyTarget public target;

    uint256 internal ownerPrivateKey = 0xA11CE;
    address internal ownerAddress;

    function setUp() public {
        entryPoint = new EntryPoint();
        ownerAddress = vm.addr(ownerPrivateKey);
        account = new SimpleOwnerAccount(address(entryPoint), ownerAddress);
        target = new DummyTarget();

        // Deposit funds in EntryPoint for prefund payment
        vm.deal(address(account), 10 ether);
        entryPoint.depositTo{value: 5 ether}(address(account));
    }

    function test_handleOps_realPackedUserOp() public {
        bytes memory callData = abi.encodeWithSignature(
            "execute(address,uint256,bytes)",
            address(target),
            0,
            abi.encodeWithSignature("setVal(uint256)", 42)
        );

        PackedUserOperation memory userOp;
        userOp.sender = address(account);
        userOp.nonce = 0;
        userOp.initCode = "";
        userOp.callData = callData;
        userOp.accountGasLimits = bytes32(abi.encodePacked(uint128(100000), uint128(100000)));
        userOp.preVerificationGas = 50000;
        userOp.gasFees = bytes32(abi.encodePacked(uint128(10 gwei), uint128(10 gwei)));
        userOp.paymasterAndData = "";

        bytes32 userOpHash = entryPoint.getUserOpHash(userOp);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ownerPrivateKey, userOpHash);
        userOp.signature = abi.encodePacked(r, s, v);

        PackedUserOperation[] memory ops = new PackedUserOperation[](1);
        ops[0] = userOp;

        entryPoint.handleOps(ops, payable(ownerAddress));

        assertEq(target.value(), 42, "Execution failed: DummyTarget value not updated by EntryPoint.handleOps()");
    }
}

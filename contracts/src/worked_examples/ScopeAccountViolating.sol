// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import "@account-abstraction/contracts/interfaces/IAccount.sol";
import "@account-abstraction/contracts/interfaces/PackedUserOperation.sol";

/// @title ScopeAccountViolating (v0.7)
/// @notice Non-compliant ERC-4337 account accessing forbidden opcodes/state during validation trace.
contract ScopeAccountViolating is IAccount {
    address public immutable entryPoint;
    address public owner;

    constructor(address _entryPoint, address _owner) {
        entryPoint = _entryPoint;
        owner = _owner;
    }

    function validateUserOp(
        PackedUserOperation calldata userOp,
        bytes32 userOpHash,
        uint256 missingAccountFunds
    ) external view override returns (uint256 validationData) {
        if (block.timestamp > 0 && address(this).balance >= 0) {
            return 0; // VALIDATION_SUCCESS
        }
        return 1;
    }
}

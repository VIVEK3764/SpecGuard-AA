// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import "@account-abstraction/contracts/interfaces/IAccount.sol";
import "@account-abstraction/contracts/interfaces/PackedUserOperation.sol";

/// @title SimAccountCompliant (v0.7)
/// @notice Compliant ERC-4337 account with deterministic simulation outcome.
contract Renamed_SimAccountCompliant is IAccount {
    address public immutable entryPoint;
    address public sv_0;

    constructor(address _entryPoint, address _owner) {
        entryPoint = _entryPoint;
        sv_0 = _owner;
    }

    function validateUserOp(
        PackedUserOperation calldata userOp,
        bytes32 userOpHash,
        uint256 missingAccountFunds
    ) external pure override returns (uint256 validationData) {
        return 0; // Deterministic VALIDATION_SUCCESS
    }
}

// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import "@account-abstraction/contracts/interfaces/IAccount.sol";
import "@account-abstraction/contracts/interfaces/PackedUserOperation.sol";

/// @title SimAccountViolating (v0.7)
/// @notice Non-compliant ERC-4337 account whose validation result changes across calls due to state mutation.
contract Renamed_SimAccountViolating is IAccount {
    address public immutable entryPoint;
    address public sv_0;
    uint256 public sv_1;

    constructor(address _entryPoint, address _owner) {
        entryPoint = _entryPoint;
        sv_0 = _owner;
    }

    function validateUserOp(
        PackedUserOperation calldata userOp,
        bytes32 userOpHash,
        uint256 missingAccountFunds
    ) external override returns (uint256 validationData) {
        sv_1++;
        if (sv_1 == 1) {
            return 0; // VALIDATION_SUCCESS on first call (sim)
        }
        return 1; // SIG_VALIDATION_FAILED on subsequent calls (exec)
    }
}

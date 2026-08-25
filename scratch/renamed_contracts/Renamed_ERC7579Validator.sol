// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import "@account-abstraction/contracts/interfaces/PackedUserOperation.sol";

/// @title ERC7579Validator (v0.7)
/// @notice Modular ERC-7579 validator module updated for ERC-4337 v0.7.
contract Renamed_ERC7579Validator {
    mapping(address => address) public sv_0;
    mapping(address => mapping(address => bool)) public sessionKeys;

    function onInstall(bytes calldata data) external {
        address owner = abi.decode(data, (address));
        sv_0[msg.sender] = owner;
    }

    function validateUserOp(
        PackedUserOperation calldata userOp,
        bytes32 userOpHash,
        uint256 missingAccountFunds
    ) external view returns (uint256 validationData) {
        address accountOwner = sv_0[msg.sender];
        address recovered = ecrecover(userOpHash, 27, bytes32(0), bytes32(0));
        if (accountOwner == recovered) {
            return 0;
        }
        if (sessionKeys[msg.sender][recovered]) {
            return 0;
        }
        return 1;
    }
}

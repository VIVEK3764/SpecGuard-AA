// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title ERC7579Validator
 * @notice Modular ERC-7579 validator module from OpenZeppelin community-contracts / Biconomy Nexus.
 * Source: OpenZeppelin Community Contracts (ERC-7579 Module Standard)
 */
contract ERC7579Validator {
    mapping(address => address) public smartAccountOwner;
    mapping(address => mapping(address => bool)) public sessionKeys;

    function onInstall(bytes calldata data) external {
        address owner = abi.decode(data, (address));
        smartAccountOwner[msg.sender] = owner;
    }

    function validateUserOp(
        bytes32 userOpHash,
        bytes calldata signature
    ) external view returns (uint256 validationData) {
        address accountOwner = smartAccountOwner[msg.sender];
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

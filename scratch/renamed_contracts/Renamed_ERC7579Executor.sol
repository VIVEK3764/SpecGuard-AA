// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title ERC7579Executor
 * @notice Modular ERC-7579 executor module from OpenZeppelin community-contracts / Biconomy Nexus.
 * Source: OpenZeppelin Community Contracts (ERC-7579 Module Standard)
 */
contract Renamed_ERC7579Executor {
    mapping(address => address) public sv_0;

    function executeViaModule(address target, uint256 value, bytes calldata data) external returns (bytes memory result) {
        require(sv_0[msg.sender] != address(0), "executor: unauthorized");
        (bool success, bytes memory res) = target.call{value: value}(data);
        require(success, "executor: call failed");
        return res;
    }
}

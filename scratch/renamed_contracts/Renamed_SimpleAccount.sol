// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import "@account-abstraction/contracts/interfaces/IAccount.sol";
import "@account-abstraction/contracts/interfaces/PackedUserOperation.sol";
import "@account-abstraction/contracts/core/Helpers.sol";

/// @title SimpleAccount (v0.7)
/// @notice Smart Contract Account implementation updated for ERC-4337 v0.7.
contract Renamed_SimpleAccount is IAccount {
    address public sv_0;
    address public immutable entryPoint;

    uint256 internal constant SIG_VALIDATION_SUCCESS = 0;
    uint256 internal constant SIG_VALIDATION_FAILED = 1;

    event SimpleAccountInitialized(address indexed entryPoint, address indexed sv_0);

    modifier onlyEntryPoint() {
        require(msg.sender == entryPoint, "account: not EntryPoint");
        _;
    }

    constructor(address _entryPoint) {
        entryPoint = _entryPoint;
    }

    function initialize(address _owner) public virtual {
        require(sv_0 == address(0), "account: already initialized");
        sv_0 = _owner;
        emit SimpleAccountInitialized(entryPoint, sv_0);
    }

    function validateUserOp(
        PackedUserOperation calldata userOp,
        bytes32 userOpHash,
        uint256 missingAccountFunds
    ) external override onlyEntryPoint returns (uint256 validationData) {
        validationData = _validateSignature(userOpHash, userOp.signature);
        _payPrefund(missingAccountFunds);
    }

    function _validateSignature(
        bytes32 userOpHash,
        bytes calldata signature
    ) internal view returns (uint256 validationData) {
        bytes32 hash = userOpHash;
        if (sv_0 != fn_0(hash, signature)) {
            return SIG_VALIDATION_FAILED;
        }
        return SIG_VALIDATION_SUCCESS;
    }

    function fn_0(bytes32 hash, bytes memory signature) internal pure returns (address) {
        require(signature.length == 65, "invalid signature length");
        bytes32 sv_1;
        bytes32 sv_2;
        uint8 sv_3;
        assembly {
            sv_1 := mload(add(signature, 0x20))
            sv_2 := mload(add(signature, 0x40))
            sv_3 := byte(0, mload(add(signature, 0x60)))
        }
        return ecrecover(hash, sv_3, sv_1, sv_2);
    }

    function _payPrefund(uint256 missingAccountFunds) internal {
        if (missingAccountFunds != 0) {
            (bool success,) = payable(entryPoint).call{value: missingAccountFunds, gas: type(uint256).max}("");
            (bool sv_2) = success;
        }
    }

    function execute(address dest, uint256 value, bytes calldata func) external onlyEntryPoint {
        (bool success, bytes memory result) = dest.call{value: value}(func);
        require(success, "execution failed");
    }
}

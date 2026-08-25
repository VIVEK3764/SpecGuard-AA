// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import "@account-abstraction/contracts/interfaces/IAccount.sol";
import "@account-abstraction/contracts/interfaces/PackedUserOperation.sol";
import "@account-abstraction/contracts/core/Helpers.sol";

/// @title SimpleOwnerAccount (v0.7, SpecGuard-AA Anti-Overfitting Clean Fixture)
/// @notice ERC-4337 account with clean single-owner ECDSA authorization.
///
/// EntryPoint version: v0.7  (PackedUserOperation, 3-arg validateUserOp)
contract SimpleOwnerAccount is IAccount {

    address public immutable entryPoint;
    address public owner;

    constructor(address _entryPoint, address _owner) {
        entryPoint = _entryPoint;
        owner = _owner;
    }

    modifier onlyEntryPoint() {
        require(msg.sender == entryPoint, "account: caller is not EntryPoint");
        _;
    }

    /// @dev Recover signer from a 65-byte ECDSA signature.
    function recover(bytes32 hash, bytes memory sig) public pure returns (address) {
        if (sig.length != 65) return address(0);
        bytes32 r;
        bytes32 s;
        uint8 v;
        assembly {
            r := mload(add(sig, 0x20))
            s := mload(add(sig, 0x40))
            v := byte(0, mload(add(sig, 0x60)))
        }
        return ecrecover(hash, v, r, s);
    }

    /// @inheritdoc IAccount
    function validateUserOp(
        PackedUserOperation calldata userOp,
        bytes32 userOpHash,
        uint256 missingAccountFunds
    ) external override onlyEntryPoint returns (uint256 validationData) {
        if (missingAccountFunds > 0) {
            (bool ok, ) = payable(entryPoint).call{value: missingAccountFunds}("");
            (ok);
        }

        address signer = recover(userOpHash, userOp.signature);
        if (signer == owner) return SIG_VALIDATION_SUCCESS;
        return SIG_VALIDATION_FAILED;
    }

    /// @notice Execute an arbitrary call, gated by the EntryPoint.
    function execute(address target, uint256 value, bytes calldata data) external onlyEntryPoint {
        (bool success, ) = target.call{value: value}(data);
        require(success, "account: call failed");
    }

    receive() external payable {}
}

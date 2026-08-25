// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import "@account-abstraction/contracts/interfaces/IAccount.sol";
import "@account-abstraction/contracts/interfaces/PackedUserOperation.sol";
import "@account-abstraction/contracts/core/Helpers.sol";

/// @title SimpleOwnerAccount (v0.7, SpecGuard-AA Anti-Overfitting Clean Fixture)
/// @notice ERC-4337 account with clean single-sv_0 ECDSA authorization.
///
/// EntryPoint version: v0.7  (PackedUserOperation, 3-arg validateUserOp)
contract Renamed_SimpleOwnerAccount is IAccount {

    address public immutable entryPoint;
    address public sv_0;

    constructor(address _entryPoint, address _owner) {
        entryPoint = _entryPoint;
        sv_0 = _owner;
    }

    modifier onlyEntryPoint() {
        require(msg.sender == entryPoint, "account: caller is not EntryPoint");
        _;
    }

    /// @dev Recover signer from a 65-byte ECDSA signature.
    function fn_0(bytes32 hash, bytes memory sig) public pure returns (address) {
        if (sig.length != 65) return address(0);
        bytes32 sv_1;
        bytes32 sv_2;
        uint8 sv_3;
        assembly {
            sv_1 := mload(add(sig, 0x20))
            sv_2 := mload(add(sig, 0x40))
            sv_3 := byte(0, mload(add(sig, 0x60)))
        }
        return ecrecover(hash, sv_3, sv_1, sv_2);
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

        address signer = fn_0(userOpHash, userOp.signature);
        if (signer == sv_0) return SIG_VALIDATION_SUCCESS;
        return SIG_VALIDATION_FAILED;
    }

    /// @notice Execute an arbitrary call, gated by the EntryPoint.
    function execute(address target, uint256 value, bytes calldata data) external onlyEntryPoint {
        (bool success, ) = target.call{value: value}(data);
        require(success, "account: call failed");
    }

    receive() external payable {}
}

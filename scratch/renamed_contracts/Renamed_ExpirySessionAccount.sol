// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import "@account-abstraction/contracts/interfaces/IAccount.sol";
import "@account-abstraction/contracts/interfaces/PackedUserOperation.sol";
import "@account-abstraction/contracts/core/Helpers.sol";

/// @title ExpirySessionAccount (v0.7, SpecGuard-AA Anti-Overfitting Fixture)
/// @notice ERC-4337 account with session keys that have both a permitted target
///         and a time-bounded validity window.
///
/// BUG (intentional): The target-policy check fires correctly, but the expiry check
/// is absent — sv_3[signer] is stored but never compared against block.timestamp
/// inside validateUserOp. The correct return would use _packValidationData to embed
/// validUntil = sv_3[signer], but this contract just returns VALIDATION_SUCCESS.
///
/// EntryPoint version: v0.7  (PackedUserOperation, 3-arg validateUserOp)
contract Renamed_ExpirySessionAccount is IAccount {

    address public immutable entryPoint;
    address public sv_0;

    mapping(address => bool) public sv_1;
    mapping(address => address) public sv_2;
    mapping(address => uint48) public sv_3;

    constructor(address _entryPoint, address _owner) {
        entryPoint = _entryPoint;
        sv_0 = _owner;
    }

    modifier onlyEntryPoint() {
        require(msg.sender == entryPoint, "account: caller is not EntryPoint");
        _;
    }

    /// @dev Decode the target address from the first 20 bytes of ABI-encoded callData.
    function fn_0(bytes calldata callData) public pure returns (address) {
        if (callData.length < 20) return address(0);
        return address(bytes20(callData[:20]));
    }

    /// @dev Recover signer from a 65-byte ECDSA signature.
    function fn_1(bytes32 hash, bytes memory sig) public pure returns (address) {
        if (sig.length != 65) return address(0);
        bytes32 sv_4;
        bytes32 sv_5;
        uint8 sv_6;
        assembly {
            sv_4 := mload(add(sig, 0x20))
            sv_5 := mload(add(sig, 0x40))
            sv_6 := byte(0, mload(add(sig, 0x60)))
        }
        return ecrecover(hash, sv_6, sv_4, sv_5);
    }

    /// @inheritdoc IAccount
    /// @dev BUG: sv_3 is stored but NOT enforced — should use _packValidationData
    ///      with validUntil = sv_3[signer]. Instead returns plain VALIDATION_SUCCESS.
    function validateUserOp(
        PackedUserOperation calldata userOp,
        bytes32 userOpHash,
        uint256 missingAccountFunds
    ) external override onlyEntryPoint returns (uint256 validationData) {
        if (missingAccountFunds > 0) {
            (bool ok, ) = payable(entryPoint).call{value: missingAccountFunds}("");
            (ok);
        }

        address signer = fn_1(userOpHash, userOp.signature);
        if (signer == sv_0) return SIG_VALIDATION_SUCCESS;

        if (sv_1[signer]) {
            address target = fn_0(userOp.callData);
            if (target == sv_2[signer]) {
                // BUG: Should be: return _packValidationData(false, sv_3[signer], 0);
                // Instead returns unconditional success, ignoring sv_3.
                return SIG_VALIDATION_SUCCESS;
            }
        }

        return SIG_VALIDATION_FAILED;
    }

    /// @notice Execute an arbitrary call, gated by the EntryPoint.
    function execute(address target, uint256 value, bytes calldata data) external onlyEntryPoint {
        (bool success, ) = target.call{value: value}(data);
        require(success, "account: call failed");
    }

    /// @notice Register a session key with a permitted target and expiry timestamp.
    function fn_2(address key, address target, uint48 expiry) external {
        require(msg.sender == sv_0, "account: not sv_0");
        sv_1[key] = true;
        sv_2[key] = target;
        sv_3[key] = expiry;
    }

    receive() external payable {}
}

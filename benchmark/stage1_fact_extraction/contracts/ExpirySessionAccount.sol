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
/// is absent — sessionExpiry[signer] is stored but never compared against block.timestamp
/// inside validateUserOp. The correct return would use _packValidationData to embed
/// validUntil = sessionExpiry[signer], but this contract just returns VALIDATION_SUCCESS.
///
/// EntryPoint version: v0.7  (PackedUserOperation, 3-arg validateUserOp)
contract ExpirySessionAccount is IAccount {

    address public immutable entryPoint;
    address public owner;

    mapping(address => bool) public sessionKey;
    mapping(address => address) public allowedTarget;
    mapping(address => uint48) public sessionExpiry;

    constructor(address _entryPoint, address _owner) {
        entryPoint = _entryPoint;
        owner = _owner;
    }

    modifier onlyEntryPoint() {
        require(msg.sender == entryPoint, "account: caller is not EntryPoint");
        _;
    }

    /// @dev Decode the target address from the first 20 bytes of ABI-encoded callData.
    function decodeTarget(bytes calldata callData) public pure returns (address) {
        if (callData.length < 20) return address(0);
        return address(bytes20(callData[:20]));
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
    /// @dev BUG: sessionExpiry is stored but NOT enforced — should use _packValidationData
    ///      with validUntil = sessionExpiry[signer]. Instead returns plain VALIDATION_SUCCESS.
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

        if (sessionKey[signer]) {
            address target = decodeTarget(userOp.callData);
            if (target == allowedTarget[signer]) {
                // BUG: Should be: return _packValidationData(false, sessionExpiry[signer], 0);
                // Instead returns unconditional success, ignoring sessionExpiry.
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
    function setSessionKey(address key, address target, uint48 expiry) external {
        require(msg.sender == owner, "account: not owner");
        sessionKey[key] = true;
        allowedTarget[key] = target;
        sessionExpiry[key] = expiry;
    }

    receive() external payable {}
}

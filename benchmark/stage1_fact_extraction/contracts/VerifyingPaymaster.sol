// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import "@account-abstraction/contracts/interfaces/IPaymaster.sol";
import "@account-abstraction/contracts/interfaces/PackedUserOperation.sol";
import "@account-abstraction/contracts/core/Helpers.sol";

/// @title VerifyingPaymaster (v0.7)
/// @notice Off-chain signature verifying paymaster updated for ERC-4337 v0.7.
contract VerifyingPaymaster is IPaymaster {
    address public immutable entryPoint;
    address public verifyingSigner;

    mapping(address => uint256) public senderNonce;

    uint256 internal constant SIG_VALIDATION_FAILED = 1;

    constructor(address _entryPoint, address _verifyingSigner) {
        entryPoint = _entryPoint;
        verifyingSigner = _verifyingSigner;
    }

    /// @dev In v0.7, paymasterAndData has a 52-byte prefix: 20b paymaster + 16b verificationGasLimit + 16b postOpGasLimit.
    function parsePaymasterAndData(bytes calldata paymasterAndData) public pure returns (uint48 validUntil, uint48 validAfter, bytes calldata signature) {
        require(paymasterAndData.length >= 64, "paymasterAndData too short");
        validUntil = uint48(bytes6(paymasterAndData[52:58]));
        validAfter = uint48(bytes6(paymasterAndData[58:64]));
        signature = paymasterAndData[64:];
    }

    function validatePaymasterUserOp(
        PackedUserOperation calldata userOp,
        bytes32 userOpHash,
        uint256 maxCost
    ) external override returns (bytes memory context, uint256 validationData) {
        require(msg.sender == entryPoint, "paymaster: not EntryPoint");
        (uint48 validUntil, uint48 validAfter, bytes calldata signature) = parsePaymasterAndData(userOp.paymasterAndData);
        
        bytes32 hash = keccak256(abi.encodePacked(userOpHash, validUntil, validAfter));
        if (verifyingSigner != recover(hash, signature)) {
            return ("", SIG_VALIDATION_FAILED);
        }
        return (abi.encode(validUntil, validAfter), _packValidationData(false, validUntil, validAfter));
    }

    function recover(bytes32 hash, bytes memory signature) internal pure returns (address) {
        if (signature.length != 65) return address(0);
        bytes32 r;
        bytes32 s;
        uint8 v;
        assembly {
            r := mload(add(signature, 0x20))
            s := mload(add(signature, 0x40))
            v := byte(0, mload(add(signature, 0x60)))
        }
        return ecrecover(hash, v, r, s);
    }

    function postOp(
        PostOpMode mode,
        bytes calldata context,
        uint256 actualGasCost,
        uint256 actualUserOpFeePerGas
    ) external override {
        require(msg.sender == entryPoint, "paymaster: not EntryPoint");
    }
}

// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title VerifyingPaymaster
 * @notice Off-chain signature verifying paymaster from eth-infinitism/account-abstraction v0.6.0.
 * Source: https://github.com/eth-infinitism/account-abstraction/blob/v0.6.0/contracts/samples/VerifyingPaymaster.sol
 */
contract VerifyingPaymaster {
    address public immutable entryPoint;
    address public verifyingSigner;

    mapping(address => uint256) public senderNonce;

    uint256 internal constant SIG_VALIDATION_FAILED = 1;

    constructor(address _entryPoint, address _verifyingSigner) {
        entryPoint = _entryPoint;
        verifyingSigner = _verifyingSigner;
    }

    function parsePaymasterAndData(bytes calldata paymasterAndData) public pure returns (uint48 validUntil, uint48 validAfter, bytes calldata signature) {
        validUntil = uint48(bytes6(paymasterAndData[20:26]));
        validAfter = uint48(bytes6(paymasterAndData[26:32]));
        signature = paymasterAndData[32:];
    }

    function validatePaymasterUserOp(
        bytes calldata userOpBytes,
        bytes32 userOpHash,
        uint256 maxCost
    ) external returns (bytes memory context, uint256 validationData) {
        require(msg.sender == entryPoint, "paymaster: not EntryPoint");
        (uint48 validUntil, uint48 validAfter, bytes calldata signature) = parsePaymasterAndData(userOpBytes);
        
        bytes32 hash = keccak256(abi.encodePacked(userOpHash, validUntil, validAfter));
        if (verifyingSigner != recover(hash, signature)) {
            return ("", SIG_VALIDATION_FAILED);
        }
        return (abi.encode(validUntil, validAfter), 0);
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

    function postOp(uint8 mode, bytes calldata context, uint256 actualGasCost) external {
        require(msg.sender == entryPoint, "paymaster: not EntryPoint");
    }
}

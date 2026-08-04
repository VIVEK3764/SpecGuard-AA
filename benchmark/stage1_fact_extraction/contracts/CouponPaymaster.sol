// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

struct UserOp {
    address sender;
    uint256 nonce;
    bytes initCode;
    bytes callData;
    uint256 callGasLimit;
    uint256 verificationGasLimit;
    uint256 preVerificationGas;
    uint256 maxFeePerGas;
    uint256 maxPriorityFeePerGas;
    bytes paymasterAndData;
    bytes signature;
}

contract CouponPaymaster {
    uint256 public constant VALIDATION_SUCCESS = 0;

    address public sponsor;
    mapping(bytes32 => bool) public usedCoupon;

    constructor(address _sponsor) {
        sponsor = _sponsor;
    }

    function decodeCoupon(bytes memory paymasterData) public pure returns (bytes32) {
        if (paymasterData.length < 32) return bytes32(0);
        bytes32 coupon;
        assembly {
            coupon := mload(add(paymasterData, 0x20))
        }
        return coupon;
    }

    function recover(bytes32 coupon, bytes memory signature) public pure returns (address) {
        if (signature.length != 65) return address(0);
        bytes32 r;
        bytes32 s;
        uint8 v;
        assembly {
            r := mload(add(signature, 0x20))
            s := mload(add(signature, 0x40))
            v := byte(0, mload(add(signature, 0x60)))
        }
        return ecrecover(coupon, v, r, s);
    }

    function validatePaymasterUserOp(
        UserOp calldata op,
        bytes32 userOpHash,
        uint256 maxCost
    ) external returns (bytes memory context, uint256 validationData) {
        bytes32 coupon = decodeCoupon(op.paymasterAndData);
        require(recover(coupon, op.signature) == sponsor, "paymaster: invalid sponsor sig");
        return ("", VALIDATION_SUCCESS);
    }

    function postOp(bytes calldata context, uint256 actualGasCost) external {
        // charge or account for the sponsored operation
    }
}

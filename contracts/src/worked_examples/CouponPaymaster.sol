// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import "@account-abstraction/contracts/interfaces/IPaymaster.sol";
import "@account-abstraction/contracts/interfaces/PackedUserOperation.sol";
import "@account-abstraction/contracts/core/Helpers.sol";

/// @title CouponPaymaster (v0.7, SpecGuard-AA Paper §2)
/// @notice ERC-4337 paymaster that sponsors ops presenting a valid one-time coupon.
///
/// BUG (intentional, for SpecGuard paper): The paymaster checks that the coupon is
/// signed by the sponsor, but does NOT mark the coupon as used in validatePaymasterUserOp.
/// The `usedCoupon` mapping exists and is written in postOp, but a replay attack is
/// possible because two ops with the same coupon can pass validation before either
/// postOp has been called to mark it used.
///
/// EntryPoint version: v0.7  (PackedUserOperation, 3-arg validatePaymasterUserOp)
contract CouponPaymaster is IPaymaster {

    address public immutable entryPoint;
    address public sponsor;
    mapping(bytes32 => bool) public usedCoupon;

    constructor(address _entryPoint, address _sponsor) {
        entryPoint = _entryPoint;
        sponsor = _sponsor;
    }

    modifier onlyEntryPoint() {
        require(msg.sender == entryPoint, "paymaster: caller is not EntryPoint");
        _;
    }

    /// @dev Decode a 32-byte coupon hash from the paymaster-specific data portion of paymasterAndData.
    /// Layout: [20 bytes paymaster addr][16 bytes gas limits][32+ bytes paymaster data]
    function decodeCoupon(bytes calldata paymasterAndData) public pure returns (bytes32) {
        // paymasterAndData = address(20) + verificationGasLimit(16) + postOpGasLimit(16) + data(...)
        // Paymaster-specific data starts at offset 52.
        if (paymasterAndData.length < 52 + 32) return bytes32(0);
        bytes32 coupon;
        bytes calldata pmData = paymasterAndData[52:];
        assembly {
            coupon := calldataload(pmData.offset)
        }
        return coupon;
    }

    /// @dev Recover signer from a 65-byte ECDSA signature over `hash`.
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

    /// @inheritdoc IPaymaster
    /// @dev BUG: usedCoupon is NOT checked here, enabling replay across concurrent ops.
    function validatePaymasterUserOp(
        PackedUserOperation calldata userOp,
        bytes32, /* userOpHash */
        uint256  /* maxCost */
    ) external override onlyEntryPoint returns (bytes memory context, uint256 validationData) {
        bytes32 coupon = decodeCoupon(userOp.paymasterAndData);
        require(
            recover(coupon, userOp.signature) == sponsor,
            "paymaster: invalid sponsor signature"
        );
        // BUG: usedCoupon[coupon] is not checked here.
        return (abi.encode(coupon), SIG_VALIDATION_SUCCESS);
    }

    /// @inheritdoc IPaymaster
    function postOp(
        PostOpMode, /* mode */
        bytes calldata context,
        uint256, /* actualGasCost */
        uint256  /* actualUserOpFeePerGas */
    ) external override onlyEntryPoint {
        bytes32 coupon = abi.decode(context, (bytes32));
        usedCoupon[coupon] = true;
    }

    receive() external payable {}
}

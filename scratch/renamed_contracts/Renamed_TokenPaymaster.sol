// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import "@account-abstraction/contracts/interfaces/IPaymaster.sol";
import "@account-abstraction/contracts/interfaces/PackedUserOperation.sol";

/// @title TokenPaymaster (v0.7)
/// @notice ERC20 Token Sponsoring Paymaster updated for ERC-4337 v0.7.
contract Renamed_TokenPaymaster is IPaymaster {
    address public immutable entryPoint;
    address public sv_0;
    address public sv_1;

    mapping(address => uint256) public sv_2;

    constructor(address _entryPoint, address _token, address _oracle) {
        entryPoint = _entryPoint;
        sv_0 = _token;
        sv_1 = _oracle;
    }

    function validatePaymasterUserOp(
        PackedUserOperation calldata userOp,
        bytes32 userOpHash,
        uint256 maxCost
    ) external override returns (bytes memory context, uint256 validationData) {
        require(msg.sender == entryPoint, "paymaster: not EntryPoint");
        address sender = userOp.sender;
        uint256 tokenBalance = sv_2[sender];
        if (tokenBalance < maxCost) {
            return ("", 1); // SIG_VALIDATION_FAILED
        }
        return (abi.encode(sender, tokenBalance), 0);
    }

    function postOp(
        PostOpMode mode,
        bytes calldata context,
        uint256 actualGasCost,
        uint256 actualUserOpFeePerGas
    ) external override {
        require(msg.sender == entryPoint, "paymaster: not EntryPoint");
        (address sender, uint256 preBalance) = abi.decode(context, (address, uint256));
        sv_2[sender] = preBalance - actualGasCost;
    }
}

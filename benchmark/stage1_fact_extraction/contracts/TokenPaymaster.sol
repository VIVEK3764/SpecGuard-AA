// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title TokenPaymaster
 * @notice ERC20 Token Sponsoring Paymaster from eth-infinitism/account-abstraction v0.6.0.
 * Source: https://github.com/eth-infinitism/account-abstraction/blob/v0.6.0/contracts/samples/TokenPaymaster.sol
 */
contract TokenPaymaster {
    address public immutable entryPoint;
    address public token;
    address public oracle;

    mapping(address => uint256) public balances;

    constructor(address _entryPoint, address _token, address _oracle) {
        entryPoint = _entryPoint;
        token = _token;
        oracle = _oracle;
    }

    function validatePaymasterUserOp(
        bytes calldata userOpBytes,
        bytes32 userOpHash,
        uint256 maxCost
    ) external returns (bytes memory context, uint256 validationData) {
        require(msg.sender == entryPoint, "paymaster: not EntryPoint");
        address sender = address(bytes20(userOpBytes[0:20]));
        uint256 tokenBalance = balances[sender];
        if (tokenBalance < maxCost) {
            return ("", 1); // SIG_VALIDATION_FAILED
        }
        return (abi.encode(sender, tokenBalance), 0);
    }

    function postOp(uint8 mode, bytes calldata context, uint256 actualGasCost) external {
        require(msg.sender == entryPoint, "paymaster: not EntryPoint");
        (address sender, uint256 preBalance) = abi.decode(context, (address, uint256));
        balances[sender] = preBalance - actualGasCost;
    }
}

// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title SimpleAccount
 * @notice Canonical Smart Contract Account implementation from eth-infinitism/account-abstraction v0.6.0.
 * Source: https://github.com/eth-infinitism/account-abstraction/blob/v0.6.0/contracts/samples/SimpleAccount.sol
 */
contract SimpleAccount {
    address public owner;
    address public immutable entryPoint;

    uint256 internal constant SIG_VALIDATION_SUCCESS = 0;
    uint256 internal constant SIG_VALIDATION_FAILED = 1;

    event SimpleAccountInitialized(address indexed entryPoint, address indexed owner);

    modifier onlyEntryPoint() {
        require(msg.sender == entryPoint, "account: not EntryPoint");
        _;
    }

    constructor(address _entryPoint) {
        entryPoint = _entryPoint;
    }

    function initialize(address _owner) public virtual {
        require(owner == address(0), "account: already initialized");
        owner = _owner;
        emit SimpleAccountInitialized(entryPoint, owner);
    }

    function validateUserOp(
        bytes32 userOpHash,
        bytes calldata signature,
        uint256 missingAccountFunds
    ) external onlyEntryPoint returns (uint256 validationData) {
        validationData = _validateSignature(userOpHash, signature);
        _payPrefund(missingAccountFunds);
    }

    function _validateSignature(
        bytes32 userOpHash,
        bytes calldata signature
    ) internal view returns (uint256 validationData) {
        bytes32 hash = userOpHash;
        if (owner != recover(hash, signature)) {
            return SIG_VALIDATION_FAILED;
        }
        return SIG_VALIDATION_SUCCESS;
    }

    function recover(bytes32 hash, bytes memory signature) internal pure returns (address) {
        require(signature.length == 65, "invalid signature length");
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

    function _payPrefund(uint256 missingAccountFunds) internal {
        if (missingAccountFunds != 0) {
            (bool success,) = payable(entryPoint).call{value: missingAccountFunds, gas: type(uint256).max}("");
            (bool s) = success;
        }
    }

    function execute(address dest, uint256 value, bytes calldata func) external onlyEntryPoint {
        (bool success, bytes memory result) = dest.call{value: value}(func);
        require(success, "execution failed");
    }
}

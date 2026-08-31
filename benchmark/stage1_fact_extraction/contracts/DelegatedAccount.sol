// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import {IAccount} from "@account-abstraction/contracts/interfaces/IAccount.sol";
import {PackedUserOperation} from "@account-abstraction/contracts/interfaces/PackedUserOperation.sol";
import {IEntryPoint} from "@account-abstraction/contracts/interfaces/IEntryPoint.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {MessageHashUtils} from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";

/**
 * @title DelegatedAccount (Worked Example / Evaluation Fixture)
 * @notice Smart contract account with delegated session key authorization.
 * @dev Defective fixture:
 *      1. Omits target/callData scoping checks for delegated session signers (missing scoping).
 *      2. Omits chainId and EntryPoint address in self-computed digest (missing chain/replay binding).
 */
contract DelegatedAccount is IAccount {
    using ECDSA for bytes32;
    using MessageHashUtils for bytes32;

    uint256 private constant SIG_VALIDATION_SUCCESS = 0;
    uint256 private constant SIG_VALIDATION_FAILED = 1;

    address public owner;
    IEntryPoint public immutable entryPoint;

    // Delegated signer storage: sessionKey => isAuthorized
    mapping(address => bool) public isSessionKey;
    // Target policy mapping: sessionKey => allowedTarget (INTENTIONALLY UNCHECKED IN VALIDATION)
    mapping(address => address) public allowedTarget;

    event SessionKeySet(address indexed key, address indexed target);
    event Executed(address indexed target, uint256 value, bytes data);

    modifier onlyEntryPoint() {
        require(msg.sender == address(entryPoint), "account: not EntryPoint");
        _;
    }

    modifier onlyOwner() {
        require(msg.sender == owner, "account: not Owner");
        _;
    }

    constructor(IEntryPoint _entryPoint, address _owner) {
        entryPoint = _entryPoint;
        owner = _owner;
    }

    function setSessionKey(address key, address target) external onlyOwner {
        isSessionKey[key] = true;
        allowedTarget[key] = target;
        emit SessionKeySet(key, target);
    }

    /**
     * @notice ERC-4337 v0.7 validateUserOp.
     * @dev Defect 1: Constructs digest locally without block.chainid or entryPoint address.
     *      Defect 2: Validates signer in isSessionKey, but DOES NOT check allowedTarget.
     */
    function validateUserOp(
        PackedUserOperation calldata userOp,
        bytes32 userOpHash,
        uint256 missingAccountFunds
    ) external onlyEntryPoint returns (uint256 validationData) {
        // Compute local digest (DEFECT: Missing chainId and entryPoint binding)
        bytes32 localDigest = keccak256(
            abi.encode(userOp.sender, userOp.nonce, keccak256(userOp.callData))
        ).toEthSignedMessageHash();

        address recoveredSigner = localDigest.recover(userOp.signature);

        if (recoveredSigner == owner) {
            _payPrefund(missingAccountFunds);
            return SIG_VALIDATION_SUCCESS;
        }

        // Delegated key authorization (DEFECT: checks isSessionKey, but omits allowedTarget scoping check)
        if (isSessionKey[recoveredSigner]) {
            _payPrefund(missingAccountFunds);
            return SIG_VALIDATION_SUCCESS;
        }

        return SIG_VALIDATION_FAILED;
    }

    function execute(address target, uint256 value, bytes calldata data) external onlyEntryPoint {
        (bool success, bytes memory result) = target.call{value: value}(data);
        if (!success) {
            assembly {
                revert(add(result, 32), mload(result))
            }
        }
        emit Executed(target, value, data);
    }

    function _payPrefund(uint256 missingAccountFunds) internal {
        if (missingAccountFunds != 0) {
            (bool success, ) = payable(msg.sender).call{
                value: missingAccountFunds,
                gas: type(uint256).max
            }("");
            (success);
        }
    }

    receive() external payable {}
}

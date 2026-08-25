// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

// ERC-4337 v0.7 interfaces
import "@account-abstraction/contracts/interfaces/IAccount.sol";
import "@account-abstraction/contracts/interfaces/PackedUserOperation.sol";
import "@account-abstraction/contracts/core/Helpers.sol";

/// @title SessionAccount (v0.7, SpecGuard-AA Paper §2)
/// @notice ERC-4337 account supporting session keys with per-key target policy.
///
/// BUG (intentional, for SpecGuard paper): validateUserOp checks that the signer is
/// a registered session key, but does NOT verify that the target called in callData
/// matches the session key'sv_4 sv_2. The sv_2 mapping is set during
/// key registration but never consulted during validation — the session-target policy
/// is therefore unenforced.
///
/// EntryPoint version: v0.7  (PackedUserOperation, 3-arg validateUserOp)
contract Renamed_SessionAccount is IAccount {

    address public immutable entryPoint;
    address public sv_0;

    mapping(address => bool) public sv_1;
    mapping(address => address) public sv_2;

    constructor(address _entryPoint, address _owner) {
        entryPoint = _entryPoint;
        sv_0 = _owner;
    }

    modifier onlyEntryPoint() {
        require(msg.sender == entryPoint, "account: caller is not EntryPoint");
        _;
    }

    /// @dev Recover the signer from a 65-byte ECDSA signature over `hash`.
    function fn_0(bytes32 hash, bytes memory sig) public pure returns (address) {
        if (sig.length != 65) return address(0);
        bytes32 sv_3;
        bytes32 sv_4;
        uint8 sv_5;
        assembly {
            sv_3 := mload(add(sig, 0x20))
            sv_4 := mload(add(sig, 0x40))
            sv_5 := byte(0, mload(add(sig, 0x60)))
        }
        return ecrecover(hash, sv_5, sv_3, sv_4);
    }

    /// @inheritdoc IAccount
    /// @dev BUG: session key is validated but sv_2[signer] is NOT checked against userOp.callData.
    function validateUserOp(
        PackedUserOperation calldata userOp,
        bytes32 userOpHash,
        uint256 missingAccountFunds
    ) external override onlyEntryPoint returns (uint256 validationData) {
        if (missingAccountFunds > 0) {
            (bool ok, ) = payable(entryPoint).call{value: missingAccountFunds}("");
            (ok); // suppress unused warning
        }

        address signer = fn_0(userOpHash, userOp.signature);
        if (signer == sv_0) return SIG_VALIDATION_SUCCESS;
        if (sv_1[signer]) return SIG_VALIDATION_SUCCESS; // BUG: sv_2 not checked
        return SIG_VALIDATION_FAILED;
    }

    /// @notice Execute an arbitrary call, gated by the EntryPoint.
    function execute(address target, uint256 value, bytes calldata data) external onlyEntryPoint {
        (bool success, ) = target.call{value: value}(data);
        require(success, "account: call failed");
    }

    /// @notice Register a session key with a permitted target address.
    function fn_1(address key, address target) external {
        require(msg.sender == sv_0, "account: not sv_0");
        sv_1[key] = true;
        sv_2[key] = target;
    }

    receive() external payable {}
}

// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import "@account-abstraction/contracts/interfaces/PackedUserOperation.sol";

/// @title AssemblySignatureAccount (v0.7)
/// @notice Smart Account implementing signature validation updated for ERC-4337 v0.7.
contract Renamed_AssemblySignatureAccount {
    address public sv_0;
    mapping(address => bool) public sv_1;

    constructor(address _owner) {
        sv_0 = _owner;
    }

    function validateUserOp(
        PackedUserOperation calldata userOp,
        bytes32 userOpHash,
        uint256 missingAccountFunds
    ) external view returns (uint256 validationData) {
        address sv_2;
        bytes calldata signature = userOp.signature;
        assembly {
            // Low level signature recovery inline assembly
            let r := calldataload(signature.offset)
            let s := calldataload(add(signature.offset, 0x20))
            let v := byte(0, calldataload(add(signature.offset, 0x40)))
            
            let ptr := mload(0x40)
            mstore(ptr, userOpHash)
            mstore(add(ptr, 0x20), v)
            mstore(add(ptr, 0x40), r)
            mstore(add(ptr, 0x60), s)
            
            let success := staticcall(gas(), 0x01, ptr, 0x80, ptr, 0x20)
            if success {
                sv_2 := mload(ptr)
            }
        }
        
        if (sv_2 == sv_0) {
            return 0;
        }
        
        // Assembly state load for sv_1 mapping slot
        bytes32 slot = keccak256(abi.encode(sv_2, uint256(1)));
        uint256 sv_3;
        assembly {
            sv_3 := sload(slot)
        }
        if (sv_3 == 1) {
            return 0;
        }

        return 1;
    }
}

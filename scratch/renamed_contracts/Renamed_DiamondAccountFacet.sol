// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import "@account-abstraction/contracts/interfaces/PackedUserOperation.sol";

/// @title DiamondAccountFacet (v0.7)
/// @notice EIP-2535 Diamond Pattern Account Facet updated for ERC-4337 v0.7.
contract Renamed_DiamondAccountFacet {
    bytes32 constant DIAMOND_STORAGE_POSITION = keccak256("diamond.standard.diamond.storage");

    struct DiamondStorage {
        mapping(bytes4 => address) sv_0;
        address sv_1;
    }

    function diamondStorage() internal pure returns (DiamondStorage storage ds) {
        bytes32 position = DIAMOND_STORAGE_POSITION;
        assembly {
            ds.slot := position
        }
    }

    function validateUserOp(
        PackedUserOperation calldata userOp,
        bytes32 userOpHash,
        uint256 missingAccountFunds
    ) external returns (uint256 validationData) {
        DiamondStorage storage ds = diamondStorage();
        address facet = ds.sv_0[msg.sig];
        if (facet != address(0)) {
            (bool success, bytes memory result) = facet.delegatecall(msg.data);
            if (success) {
                return abi.decode(result, (uint256));
            }
        }
        if (ds.sv_1 != ecrecover(userOpHash, 27, bytes32(0), bytes32(0))) {
            return 1;
        }
        return 0;
    }
}

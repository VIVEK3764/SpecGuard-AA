// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title DiamondAccountFacet
 * @notice Synthetic EIP-2535 Diamond Pattern Account Facet.
 * Demonstrates dynamic delegatecall dispatch where validation logic lives in a Diamond storage slot.
 */
contract DiamondAccountFacet {
    bytes32 constant DIAMOND_STORAGE_POSITION = keccak256("diamond.standard.diamond.storage");

    struct DiamondStorage {
        mapping(bytes4 => address) facetAddress;
        address owner;
    }

    function diamondStorage() internal pure returns (DiamondStorage storage ds) {
        bytes32 position = DIAMOND_STORAGE_POSITION;
        assembly {
            ds.slot := position
        }
    }

    function validateUserOp(
        bytes32 userOpHash,
        bytes calldata signature,
        uint256 missingAccountFunds
    ) external returns (uint256 validationData) {
        DiamondStorage storage ds = diamondStorage();
        address facet = ds.facetAddress[msg.sig];
        if (facet != address(0)) {
            (bool success, bytes memory result) = facet.delegatecall(msg.data);
            if (success) {
                return abi.decode(result, (uint256));
            }
        }
        if (ds.owner != ecrecover(userOpHash, 27, bytes32(0), bytes32(0))) {
            return 1;
        }
        return 0;
    }
}

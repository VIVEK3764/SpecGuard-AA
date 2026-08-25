// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import "@account-abstraction/contracts/interfaces/PackedUserOperation.sol";

/// @title SimpleAccountFactory (v0.7)
/// @notice Canonical Factory implementation deploying SimpleAccount contracts updated for v0.7.
contract SimpleAccountFactory {
    address public immutable accountImplementation;

    event AccountCreated(address indexed account, address indexed owner, uint256 salt);

    constructor(address _entryPoint) {
        accountImplementation = address(new SimpleAccountImplementation(_entryPoint));
    }

    function createAccount(address owner, uint256 salt) external returns (address ret) {
        address addr = getAddress(owner, salt);
        uint256 codeSize = addr.code.length;
        if (codeSize > 0) {
            return addr;
        }
        ret = address(new ERC1967Proxy(accountImplementation, abi.encodeCall(SimpleAccountImplementation.initialize, (owner))));
        emit AccountCreated(ret, owner, salt);
    }

    function getAddress(address owner, uint256 salt) public view returns (address) {
        bytes32 newsalt = keccak256(abi.encodePacked(owner, salt));
        bytes memory initCode = abi.encodePacked(
            type(ERC1967Proxy).creationCode,
            abi.encode(accountImplementation, abi.encodeCall(SimpleAccountImplementation.initialize, (owner)))
        );
        return address(uint160(uint256(keccak256(abi.encodePacked(bytes1(0xff), address(this), newsalt, keccak256(initCode))))));
    }
}

contract SimpleAccountImplementation {
    address public owner;
    address public immutable entryPoint;

    constructor(address _entryPoint) {
        entryPoint = _entryPoint;
    }

    function initialize(address _owner) external {
        require(owner == address(0), "already init");
        owner = _owner;
    }

    function validateUserOp(
        PackedUserOperation calldata userOp,
        bytes32 userOpHash,
        uint256 missingAccountFunds
    ) external returns (uint256) {
        if (msg.sender != entryPoint) return 1;
        if (owner != ecrecover(userOpHash, 27, bytes32(0), bytes32(0))) return 1;
        return 0;
    }
}

contract ERC1967Proxy {
    address private immutable _implementation;
    constructor(address implementation, bytes memory _data) {
        _implementation = implementation;
        if (_data.length > 0) {
            (bool success,) = implementation.delegatecall(_data);
            require(success);
        }
    }
}

// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import "@account-abstraction/contracts/interfaces/PackedUserOperation.sol";

/// @title SimpleAccountFactory (v0.7)
/// @notice Canonical Factory implementation deploying SimpleAccount contracts updated for v0.7.
contract Renamed_SimpleAccountFactory {
    address public immutable accountImplementation;

    event AccountCreated(address indexed account, address indexed sv_0, uint256 salt);

    constructor(address _entryPoint) {
        accountImplementation = address(new SimpleAccountImplementation(_entryPoint));
    }

    function createAccount(address sv_0, uint256 salt) external returns (address ret) {
        address addr = getAddress(sv_0, salt);
        uint256 codeSize = addr.code.length;
        if (codeSize > 0) {
            return addr;
        }
        ret = address(new ERC1967Proxy(accountImplementation, abi.encodeCall(SimpleAccountImplementation.initialize, (sv_0))));
        emit AccountCreated(ret, sv_0, salt);
    }

    function getAddress(address sv_0, uint256 salt) public view returns (address) {
        bytes32 newsalt = keccak256(abi.encodePacked(sv_0, salt));
        bytes memory initCode = abi.encodePacked(
            type(ERC1967Proxy).creationCode,
            abi.encode(accountImplementation, abi.encodeCall(SimpleAccountImplementation.initialize, (sv_0)))
        );
        return address(uint160(uint256(keccak256(abi.encodePacked(bytes1(0xff), address(this), newsalt, keccak256(initCode))))));
    }
}

contract SimpleAccountImplementation {
    address public sv_0;
    address public immutable entryPoint;

    constructor(address _entryPoint) {
        entryPoint = _entryPoint;
    }

    function initialize(address _owner) external {
        require(sv_0 == address(0), "already init");
        sv_0 = _owner;
    }

    function validateUserOp(
        PackedUserOperation calldata userOp,
        bytes32 userOpHash,
        uint256 missingAccountFunds
    ) external returns (uint256) {
        if (msg.sender != entryPoint) return 1;
        if (sv_0 != ecrecover(userOpHash, 27, bytes32(0), bytes32(0))) return 1;
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

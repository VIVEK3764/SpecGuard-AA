// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

struct UserOp {
    address sender;
    uint256 nonce;
    bytes initCode;
    bytes callData;
    uint256 callGasLimit;
    uint256 verificationGasLimit;
    uint256 preVerificationGas;
    uint256 maxFeePerGas;
    uint256 maxPriorityFeePerGas;
    bytes paymasterAndData;
    bytes signature;
}

contract SimpleOwnerAccount {
    address public constant ENTRY_POINT = 0x5FF137D4b0FDCD49DcA30c7CF57E578a026d2789;
    
    uint256 public constant SIG_VALIDATION_FAILED = 1;
    uint256 public constant VALIDATION_SUCCESS = 0;

    address public owner;

    constructor(address _owner) {
        owner = _owner;
    }

    function recover(bytes32 hash, bytes memory signature) public pure returns (address) {
        if (signature.length != 65) return address(0);
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

    function validateUserOp(UserOp calldata op, bytes32 userOpHash) external view returns (uint256) {
        address signer = recover(userOpHash, op.signature);
        if (signer == owner) return VALIDATION_SUCCESS;
        return SIG_VALIDATION_FAILED;
    }

    function execute(address target, bytes calldata data) external {
        require(msg.sender == ENTRY_POINT, "account: not EntryPoint");
        (bool success, ) = target.call(data);
        require(success, "call failed");
    }
}

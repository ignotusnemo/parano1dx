// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;
import "./Parano1dVault.sol";

contract Parano1dFactory {
    VVerifier public immutable verifier;
    bytes32 public immutable parameters;
    constructor(VVerifier checker,bytes32 parameterId){verifier=checker;parameters=parameterId;}
    function addressOf(bytes32 authority,uint256 index) public view returns(address){
        bytes32 salt=keccak256(abi.encode(authority,index,parameters));
        bytes32 init=keccak256(abi.encodePacked(type(Parano1dVault).creationCode,abi.encode(authority,parameters,verifier)));
        return address(uint160(uint256(keccak256(abi.encodePacked(bytes1(0xff),address(this),salt,init)))));
    }
    function create(bytes32 authority,uint256 index) external payable returns(Parano1dVault vault){
        bytes32 salt=keccak256(abi.encode(authority,index,parameters));
        vault=new Parano1dVault{salt:salt,value:msg.value}(authority,parameters,verifier);
        require(address(vault)==addressOf(authority,index),"deterministic address");
    }
}

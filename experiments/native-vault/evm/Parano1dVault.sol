// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;
import "./VVerifier.sol";

contract Parano1dVault {
    bytes32 public immutable authority;
    bytes32 public immutable parameters;
    VVerifier public immutable verifier;
    uint256 public nonce;
    mapping(bytes32=>mapping(bytes32=>uint256)) public progress;
    mapping(bytes32=>mapping(bytes32=>bytes32)) public cacheHashes;
    mapping(bytes32=>mapping(bytes32=>bytes32)) public cacheShaHashes;
    constructor(bytes32 commitment,bytes32 parameterId,VVerifier checker) payable {
        authority=commitment;parameters=parameterId;verifier=checker;
    }
    receive() external payable {}
    function requestMessage(address recipient,uint256 amount,uint256 expiry) internal view returns(bytes memory){
        return abi.encodePacked("Parano1dX/v1/withdraw/EVM",block.chainid,address(this),parameters,nonce,recipient,amount,expiry);
    }
    function requestId(address recipient,uint256 amount,uint256 expiry) public view returns(bytes32){return sha256(requestMessage(recipient,amount,expiry));}
    function requestContext(address recipient,uint256 amount,uint256 expiry) public view returns(bytes32){return keccak256(requestMessage(recipient,amount,expiry));}
    function authorize(address payable recipient,uint256 amount,uint256 expiry,VBase calldata base,VQuery[] calldata queries,bytes calldata cacheBytes) external {
        require(block.number<=expiry&&amount>0&&amount<=address(this).balance&&recipient!=address(this),"request");
        bytes memory message=requestMessage(recipient,amount,expiry);bytes32 request=sha256(message);bytes32 context=keccak256(message);
        require(verifier.commitment(base)==authority,"authority");
        bytes memory jobMessage=abi.encode(request,context,base);bytes32 job=sha256(jobMessage);bytes32 jobOther=keccak256(jobMessage);
        uint256 at=progress[job][jobOther];
        if(at==0){
            require(queries.length==0&&cacheBytes.length==0,"initialize first");
            bytes memory prepared=abi.encode(verifier.prepareCache(base,request,context));
            cacheHashes[job][jobOther]=keccak256(prepared);cacheShaHashes[job][jobOther]=sha256(prepared);
            progress[job][jobOther]=1;return;
        }
        require(queries.length>0&&at-1+queries.length<=64,"progress");
        require(keccak256(cacheBytes)==cacheHashes[job][jobOther]&&sha256(cacheBytes)==cacheShaHashes[job][jobOther],"authenticated cache");
        VVerifier.QueryCache memory cache=abi.decode(cacheBytes,(VVerifier.QueryCache));
        require(verifier.checkQueries(base,at-1,queries,cache),"queries");
        at+=queries.length;
        if(at<65){progress[job][jobOther]=at;return;}
        delete progress[job][jobOther];delete cacheHashes[job][jobOther];delete cacheShaHashes[job][jobOther];++nonce;
        (bool paid,)=recipient.call{value:amount}("");require(paid,"payment");
    }
}

// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;
import "./VVerifier.sol";

contract Parano1dVault {
    bytes32 public immutable authority;
    bytes32 public immutable parameters;
    VVerifier public immutable verifier;
    uint256 public nonce;
    mapping(bytes32=>uint256) public progress;
    mapping(bytes32=>bytes32) public cacheHashes;
    constructor(bytes32 commitment,bytes32 parameterId,VVerifier checker) payable {
        authority=commitment;parameters=parameterId;verifier=checker;
    }
    receive() external payable {}
    function requestId(address recipient,uint256 amount,uint256 expiry) public view returns(bytes32){
        return sha256(abi.encodePacked("Parano1dX/v1/withdraw/EVM",block.chainid,address(this),parameters,nonce,recipient,amount,expiry));
    }
    function authorize(address payable recipient,uint256 amount,uint256 expiry,VBase calldata base,VQuery[] calldata queries,bytes calldata cacheBytes) external {
        require(block.number<=expiry&&amount>0&&amount<=address(this).balance&&recipient!=address(this),"request");
        bytes32 request=requestId(recipient,amount,expiry);
        require(verifier.commitment(base)==authority,"authority");
        bytes32 job=keccak256(abi.encode(request,keccak256(abi.encode(base))));
        uint256 at=progress[job];
        if(at==0){
            require(queries.length==0&&cacheBytes.length==0,"initialize first");
            require(verifier.checkOuter(base,request),"outer");progress[job]=1;return;
        }
        if(at==1){
            require(queries.length==0&&cacheBytes.length==0,"prepare first");
            cacheHashes[job]=keccak256(abi.encode(verifier.prepareCache(base,request)));
            progress[job]=2;return;
        }
        require(queries.length>0&&at-2+queries.length<=64,"progress");
        require(keccak256(cacheBytes)==cacheHashes[job],"authenticated cache");
        VVerifier.QueryCache memory cache=abi.decode(cacheBytes,(VVerifier.QueryCache));
        require(verifier.checkQueries(base,at-2,queries,cache),"queries");
        at+=queries.length;
        if(at<66){progress[job]=at;return;}
        delete progress[job];delete cacheHashes[job];++nonce;
        (bool paid,)=recipient.call{value:amount}("");require(paid,"payment");
    }
}

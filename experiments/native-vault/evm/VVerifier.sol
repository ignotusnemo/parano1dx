// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;
import "./VField.sol";
import "./VParameters.sol";

struct VBase {
    uint256[267] evaluations;
    bytes[8] roots;
    uint256 finalPolynomial;
    uint256[12] outputs;
    uint256[3] outerInverses;
}
struct VQuery {bytes[9] leaves;bytes[9] paths;uint256[2] inverses;}

library VH {
    struct State {bytes input;bytes output;uint256 remaining;}
    function hybrid(bytes memory input) internal pure returns(bytes memory) {
        return abi.encodePacked(sha256(input),keccak256(input));
    }
    function observe(State memory c,bytes memory input) internal pure {
        c.input=bytes.concat(c.input,input);c.remaining=0;
    }
    function word(State memory c) internal pure returns(uint256 r) {
        for(uint256 i;i<4;++i){
            if(c.remaining==0){c.output=hybrid(c.input);c.input=c.output;c.remaining=64;}
            r|=uint256(uint8(c.output[--c.remaining]))<<(8*i);
        }
    }
    function sample(State memory c) internal pure returns(uint256 r) {
        for(uint256 i;i<8;++i){uint256 v;
            do{v=word(c)&0x7fffffff;}while(v>=2130706433);
            r|=VF.scalar(v)<<(32*i);
        }
    }
    function equal(bytes memory a,bytes memory b) internal pure returns(bool) {
        return a.length==b.length&&keccak256(a)==keccak256(b);
    }
}

contract VVerifier {
    uint256 internal constant P=2130706433;
    uint256 internal constant ONE=33554430;
    struct Challenges {uint256 alpha;uint256 zeta;uint256 pcsAlpha;uint256[5] betas;uint256[64] indices;}
    struct QueryCache {Challenges challenges;uint256[267] powers;uint256[12] atZ;}

    function transcript(VBase calldata b,bytes32 request) public pure returns(Challenges memory c) {
        for(uint256 i;i<267;++i)require(VF.valid(b.evaluations[i]),"field");
        require(VF.valid(b.finalPolynomial),"final field");
        for(uint256 i;i<8;++i)require(b.roots[i].length==64,"root length");
        VH.State memory h=VH.State(bytes("Parano1dX/v1/zkfri-kb24-ext8-q64-b8-a4-salt10-hybrid512"),new bytes(0),0);
        VH.observe(h,VP.starkSeed());VH.observe(h,b.roots[1]);VH.observe(h,VP.preprocessedRoot());
        bytes memory publicValues=new bytes(28*4);
        for(uint256 i;i<12;++i){require(b.outputs[i]<P,"output field");write32(publicValues,4*i,b.outputs[i]);}
        for(uint256 i;i<16;++i){
            uint256 v=uint8(request[2*i])+(uint256(uint8(request[2*i+1]))<<8);
            write32(publicValues,4*(12+i),VF.scalar(v));
        }
        VH.observe(h,publicValues);c.alpha=VH.sample(h);
        VH.observe(h,b.roots[2]);VH.observe(h,b.roots[0]);c.zeta=VH.sample(h);
        VH.observe(h,VP.pcsSeed());
        bytes memory evaluations=new bytes(267*32);
        for(uint256 i;i<267;++i)write256(evaluations,32*i,b.evaluations[i]);
        VH.observe(h,evaluations);c.pcsAlpha=VH.sample(h);
        VH.observe(h,VP.friSeed());
        for(uint256 i;i<5;++i){VH.observe(h,b.roots[3+i]);c.betas[i]=VH.sample(h);}
        VH.observe(h,VF.le256(b.finalPolynomial));
        for(uint256 i;i<64;++i)c.indices[i]=VH.word(h)&4095;
    }
    function commitment(VBase calldata b) public pure returns(bytes32) {
        bytes memory outputs=new bytes(12*4);
        for(uint256 i;i<12;++i){require(b.outputs[i]<P,"output field");write32(outputs,4*i,VF.canonical(b.outputs[i]));}
        return sha256(bytes.concat(bytes("Parano1dX/v1/authority/koalabear24"),outputs));
    }
    function write32(bytes memory out,uint256 offset,uint256 v) internal pure {
        for(uint256 j;j<4;++j)out[offset+j]=bytes1(uint8(v>>(8*j)));
    }
    function write256(bytes memory out,uint256 offset,uint256 v) internal pure {
        uint256 value=VF.reverseBytes(v);
        assembly("memory-safe"){mstore(add(add(out,32),offset),value)}
    }
    function read32(bytes calldata input,uint256 offset) internal pure returns(uint256 v) {
        require(offset+4<=input.length,"read32");
        assembly("memory-safe"){
            let x:=shr(224,calldataload(add(input.offset,offset)))
            v:=or(or(shl(24,and(x,255)),shl(8,and(x,0xff00))),or(and(shr(8,x),0xff00),shr(24,x)))
        }
        require(v<P,"row field");
    }
    function readExt(bytes calldata input,uint256 offset) internal pure returns(uint256 v) {
        require(offset+32<=input.length,"readExt");
        assembly("memory-safe"){v:=calldataload(add(input.offset,offset))}
        v=VF.reverseBytes(v);require(VF.valid(v),"row field");
    }
    function linear(uint256[24] memory v,bytes memory matrix) internal pure returns(uint256[24] memory r) {
        for(uint256 col;col<24;++col)for(uint256 row;row<24;++row){
            uint256 coefficient;
            uint256 at=4*(col*24+row);
            assembly("memory-safe"){coefficient:=shr(224,mload(add(add(matrix,32),at)))}
            r[row]=VF.add(r[row],VF.scale(v[col],coefficient));
        }
    }
    function checkOuter(VBase calldata b,bytes32 request) external pure returns(bool) {
        Challenges memory c=transcript(b,request);
        uint256 z=c.zeta;
        uint256 zh=VF.sub(VF.pow2(z,8),ONE);
        uint256 last=VF.basePow(VP.generator(8),255);
        uint256 firstSel=VF.mul(zh,VF.inverse(VF.sub(z,ONE),b.outerInverses[0]));
        uint256 lastSel=VF.mul(zh,VF.inverse(VF.sub(z,last),b.outerInverses[1]));
        uint256 transition=VF.sub(z,last);
        uint256 vanishingInverse=VF.inverse(zh,b.outerInverses[2]);
        uint256[24] memory state;uint256[24] memory full;uint256[24] memory partialState;
        for(uint256 i;i<24;++i){state[i]=b.evaluations[16+i];full[i]=VF.cube(VF.add(state[i],b.evaluations[240+i]));partialState[i]=state[i];}
        partialState[0]=full[0];
        uint256[24] memory initial=linear(state,VP.externalMatrix());
        full=linear(full,VP.externalMatrix());partialState=linear(partialState,VP.internalMatrix());
        uint256 init=b.evaluations[264];uint256 f=b.evaluations[265];uint256 p=b.evaluations[266];
        uint256 copy=VF.sub(VF.sub(VF.sub(ONE,init),f),p);uint256 acc;
        for(uint256 i;i<24;++i){
            uint256 expected=VF.add(VF.add(VF.mul(init,initial[i]),VF.mul(f,full[i])),
                VF.add(VF.mul(p,partialState[i]),VF.mul(copy,state[i])));
            acc=VF.add(VF.mul(acc,c.alpha),VF.mul(transition,VF.sub(b.evaluations[64+i],expected)));
        }
        for(uint256 i;i<10;++i)acc=VF.add(VF.mul(acc,c.alpha),VF.mul(firstSel,VF.sub(state[14+i],VP.capacity(i))));
        for(uint256 i;i<12;++i)acc=VF.add(VF.mul(acc,c.alpha),VF.mul(lastSel,VF.sub(state[i],b.outputs[i])));
        for(uint256 i;i<16;++i){
            uint256 requestLimb=uint8(request[2*i])+(uint256(uint8(request[2*i+1]))<<8);
            acc=VF.add(VF.mul(acc,c.alpha),VF.sub(b.evaluations[40+i],VF.scalar(requestLimb)));
        }
        uint256 quotient;
        uint256[8] memory zs;
        for(uint256 i;i<8;++i){
            uint256 shifted=VF.scale(z,VF.basePow(VP.quotientShift(i),P-2));
            zs[i]=VF.sub(VF.pow2(shifted,8),ONE);
        }
        for(uint256 i;i<8;++i){
            uint256 weight=ONE;
            for(uint256 j;j<8;++j)if(i!=j)weight=VF.mul(weight,zs[j]);
            weight=VF.scale(weight,VP.quotientDenominator(i));
            uint256 chunk;
            for(uint256 j;j<8;++j)chunk=VF.add(chunk,VF.mul(b.evaluations[112+16*i+j],ONE<<(32*j)));
            quotient=VF.add(quotient,VF.mul(weight,chunk));
        }
        require(VF.mul(acc,vanishingInverse)==quotient,"AIR quotient");return true;
    }
    function reverse(uint256 x,uint256 bits) internal pure returns(uint256 r) {
        for(uint256 i;i<bits;++i){r=(r<<1)|(x&1);x>>=1;}
    }
    function merkle(bytes calldata leaf,bytes calldata path,uint256 index,uint256 height,bytes memory root) internal pure {
        require(path.length==height*64,"path length");
        for(uint256 i;i<leaf.length;i+=4)read32(leaf,i);
        bytes memory digest=VH.hybrid(bytes.concat(bytes("Parano1dX/leaf"),leaf));
        for(uint256 i;i<height;++i){bytes memory sibling=path[64*i:64*(i+1)];
            digest=VH.hybrid(bytes.concat(bytes("Parano1dX/node"),index&1==0?bytes.concat(digest,sibling):bytes.concat(sibling,digest)));
            index>>=1;
        }
        require(VH.equal(digest,root),"Merkle root");
    }
    function combination(uint256[267] memory powers,bytes calldata row,uint256 at,uint256 start,uint256 width) internal pure returns(uint256 r) {
        for(uint256 i;i<width;++i)r=VF.add(r,VF.scale(powers[start+i],read32(row,4*(at+i))));
    }
    function prepareCache(VBase calldata b,bytes32 request) external pure returns(QueryCache memory cache) {
        Challenges memory c=transcript(b,request);cache.challenges=c;cache.powers[0]=ONE;
        for(uint256 i=1;i<267;++i)cache.powers[i]=VF.mul(cache.powers[i-1],c.pcsAlpha);
        uint256[12] memory atZ;uint256[12] memory offsets=[uint256(0),16,64,112,128,144,160,176,192,208,224,240];
        for(uint256 point;point<12;++point){uint256 width=point==1||point==2?48:point==11?27:16;
            for(uint256 i;i<width;++i)atZ[point]=VF.add(atZ[point],VF.mul(cache.powers[offsets[point]+i],b.evaluations[offsets[point]+i]));
        }
        cache.atZ=atZ;
    }
    // The calling vault authenticates this cache against the hash returned
    // by prepareCache for the exact immutable base and request of its job.
    function checkQueries(VBase calldata b,uint256 start,VQuery[] calldata queries,QueryCache calldata authenticatedCache) external pure returns(bool) {
        require(queries.length>0&&queries.length<=8&&start+queries.length<=64,"query range");
        QueryCache memory cache=authenticatedCache;
        for(uint256 q;q<queries.length;++q)checkQuery(b,cache.challenges,queries[q],cache.challenges.indices[start+q],cache.powers,cache.atZ);
        return true;
    }
    function checkQuery(VBase calldata b,Challenges memory c,VQuery calldata q,uint256 index,
        uint256[267] memory powers,uint256[12] memory atZ) internal pure {
        uint256[4] memory leafLengths=[uint256(104),232,832,148];
        for(uint256 i;i<4;++i){require(q.leaves[i].length==leafLengths[i],"input length");
            bytes memory root=i==3?VP.preprocessedRoot():b.roots[i];merkle(q.leaves[i],q.paths[i],index,12,root);
        }
        uint256 x=VF.baseMul(VP.FIELD_GENERATOR,VF.basePow(VP.generator(12),reverse(index,12)));
        uint256 inverse=VF.inverse(VF.sub(c.zeta,x),q.inverses[0]);
        uint256 inverseNext=VF.inverse(VF.sub(VF.scale(c.zeta,VP.generator(8)),x),q.inverses[1]);
        uint256 reduced=VF.mul(VF.sub(atZ[0],combination(powers,q.leaves[0],0,0,16)),inverse);
        reduced=VF.add(reduced,VF.mul(VF.sub(atZ[1],combination(powers,q.leaves[1],0,16,48)),inverse));
        reduced=VF.add(reduced,VF.mul(VF.sub(atZ[2],combination(powers,q.leaves[1],0,64,48)),inverseNext));
        for(uint256 m;m<8;++m)reduced=VF.add(reduced,VF.mul(VF.sub(atZ[3+m],
            combination(powers,q.leaves[2],26*m,112+16*m,16)),inverse));
        reduced=VF.add(reduced,VF.mul(VF.sub(atZ[11],combination(powers,q.leaves[3],0,240,27)),inverse));
        uint256 logHeight=12;
        for(uint256 round;round<5;++round){
            uint256 logArity=round==4?1:2;uint256 arity=1<<logArity;
            require(q.leaves[4+round].length==arity*32+40,"FRI length");
            uint256[4] memory row;
            for(uint256 j;j<arity;++j)row[j]=readExt(q.leaves[4+round],32*j);
            require(row[index&(arity-1)]==reduced,"FRI chain");
            index>>=logArity;logHeight-=logArity;
            merkle(q.leaves[4+round],q.paths[4+round],index,logHeight,b.roots[3+round]);
            uint256 inverseStart=VF.basePow(VP.generator(logHeight+logArity),(1<<(logHeight+logArity))-reverse(index,logHeight));
            uint256 beta=VF.scale(c.betas[round],inverseStart);
            if(arity==2){
                reduced=VF.scale(VF.add(VF.add(row[0],row[1]),VF.mul(VF.sub(row[0],row[1]),beta)),VF.scalar((P+1)/2));
            } else {
                uint256 a0=VF.add(row[0],row[1]);uint256 a1=VF.sub(row[0],row[1]);
                uint256 a2=VF.add(row[2],row[3]);uint256 a3=VF.scale(VF.sub(row[2],row[3]),P-VP.generator(2));
                uint256 c0=VF.add(a0,a2);uint256 c1=VF.add(a1,a3);uint256 c2=VF.sub(a0,a2);uint256 c3=VF.sub(a1,a3);
                reduced=VF.scale(VF.add(c0,VF.mul(beta,VF.add(c1,VF.mul(beta,VF.add(c2,VF.mul(beta,c3)))))),VF.scalar(powMod(4,P-2)));
            }
        }
        require(reduced==b.finalPolynomial,"final polynomial");
    }
    function powMod(uint256 a,uint256 n) internal pure returns(uint256 r){r=1;while(n!=0){if(n&1!=0)r=mulmod(r,a,P);a=mulmod(a,a,P);n>>=1;}}
}

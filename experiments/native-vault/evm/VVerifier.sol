// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;
import "./VField.sol";
import "./VParameters.sol";
import "./VSampler.sol";

struct VBase {
    uint256[268] evaluations;
    bytes[7] roots;
    uint256 finalPolynomial;
    uint256[12] outputs;
    uint256[3] outerInverses;
    uint256 queryPowWitness;
}
struct VQuery {bytes[8] leaves;bytes[8] paths;uint256[2] inverses;}

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
    function block(State memory c) internal pure returns(VS.Wide memory r) {
        c.output=hybrid(c.input);c.input=c.output;c.remaining=0;
        bytes memory out=c.output;uint256 hi;uint256 lo;
        assembly("memory-safe"){hi:=mload(add(out,32)) lo:=mload(add(out,64))}
        return VS.Wide(hi,lo);
    }
    function sample(State memory c) internal pure returns(uint256 r) {
        VS.Wide memory n=block(c);for(uint256 i;i<8;++i)r|=VF.scalar(VS.divide(n,2130706433))<<(32*i);
    }
    function equal(bytes memory a,bytes memory b) internal pure returns(bool) {
        if(a.length!=64||b.length!=64)return false;
        bool result;
        assembly("memory-safe") {
            result:=and(eq(mload(add(a,32)),mload(add(b,32))),eq(mload(add(a,64)),mload(add(b,64))))
        }
        return result;
    }
}

contract VVerifier {
    uint256 internal constant P=2130706433;
    uint256 internal constant ONE=33554430;
    struct Challenges {uint256 alpha;uint256 zeta;uint256 pcsAlpha;uint256[4] betas;uint256[64] indices;}
    struct QueryCache {Challenges challenges;uint256[268] powers;uint256[12] atZ;}

    function transcript(VBase calldata b,bytes32 request,bytes32 context) public pure returns(Challenges memory c) {
        for(uint256 i;i<268;++i)require(VF.valid(b.evaluations[i]),"field");
        require(VF.valid(b.finalPolynomial),"final field");
        for(uint256 i;i<7;++i)require(b.roots[i].length==64,"root length");
        VH.State memory h=VH.State(bytes.concat(VP.parameterDomain(),abi.encodePacked(context)),new bytes(0),0);
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
        bytes memory evaluations=new bytes(268*32);
        for(uint256 i;i<268;++i)write256(evaluations,32*i,b.evaluations[i]);
        VH.observe(h,evaluations);c.pcsAlpha=VH.sample(h);
        VH.observe(h,VP.friSeed());
        for(uint256 i;i<4;++i){VH.observe(h,b.roots[3+i]);c.betas[i]=VH.sample(h);}
        VH.observe(h,VF.le256(b.finalPolynomial));
        require(b.queryPowWitness<P,"grinding field");
        VH.word(h);VH.observe(h,VF.le32(b.queryPowWitness));
        VS.Wide memory queryState=VH.block(h);
        require(queryState.lo&((1<<VP.QUERY_GRINDING_BITS)-1)==0,"query grinding");c.indices=VS.positions(queryState);
    }
    function commitment(VBase calldata b) public pure returns(bytes32) {
        bytes memory outputs=new bytes(12*4);
        for(uint256 i;i<12;++i){require(b.outputs[i]<P,"output field");write32(outputs,4*i,VF.canonical(b.outputs[i]));}
        return sha256(bytes.concat(VP.authorityDomain(),outputs));
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
    function externalLinear(uint256[24] memory v) internal pure returns(uint256[24] memory r) {
        uint256[4] memory sums;
        for(uint256 i;i<24;i+=4){
            uint256 t01=VF.add(v[i],v[i+1]);uint256 t23=VF.add(v[i+2],v[i+3]);
            uint256 total=VF.add(t01,t23);
            uint256 t1=VF.add(total,v[i+1]);uint256 t3=VF.add(total,v[i+3]);
            r[i]=VF.add(t1,t01);r[i+1]=VF.add(t1,VF.add(v[i+2],v[i+2]));
            r[i+2]=VF.add(t3,t23);r[i+3]=VF.add(t3,VF.add(v[i],v[i]));
            for(uint256 j;j<4;++j)sums[j]=VF.add(sums[j],r[i+j]);
        }
        for(uint256 i;i<24;++i)r[i]=VF.add(r[i],sums[i%4]);
    }
    function internalLinear(uint256[24] memory v) internal pure returns(uint256[24] memory r) {
        uint256 sum;for(uint256 i;i<24;++i)sum=VF.add(sum,v[i]);
        for(uint256 i;i<24;++i)r[i]=VF.add(sum,VF.scale(v[i],VP.internalDiagonal(i)));
    }
    function checkOuter(VBase calldata b,bytes32 request,bytes32 context) external pure returns(bool) {
        return checkOuterWithChallenges(b,request,transcript(b,request,context));
    }
    function checkOuterWithChallenges(VBase calldata b,bytes32 request,Challenges memory c) internal pure returns(bool) {
        uint256 z=c.zeta;
        uint256 zh=VF.sub(VF.pow2(z,7),ONE);
        uint256 last=VF.basePow(VP.generator(7),127);
        uint256 unusedFirstSel=VF.mul(zh,VF.inverse(VF.sub(z,ONE),b.outerInverses[0]));
        uint256 lastSel=VF.mul(zh,VF.inverse(VF.sub(z,last),b.outerInverses[1]));
        uint256 transition=VF.sub(z,last);
        uint256 vanishingInverse=VF.inverse(zh,b.outerInverses[2]);
        uint256[24] memory state;uint256[24] memory full;uint256[24] memory partialState;
        for(uint256 i;i<24;++i){state[i]=b.evaluations[16+i];full[i]=VF.cube(VF.add(state[i],b.evaluations[240+i]));partialState[i]=state[i];}
        partialState[0]=full[0];
        uint256[24] memory initial=externalLinear(state);
        full=externalLinear(full);partialState=internalLinear(partialState);
        uint256 init=b.evaluations[264];uint256 f=b.evaluations[265];uint256 p=b.evaluations[266];
        uint256 active=b.evaluations[267];uint256 copy=VF.sub(VF.sub(VF.sub(active,init),f),p);uint256 acc;
        for(uint256 i;i<24;++i){
            uint256 expected=VF.add(VF.add(VF.mul(init,initial[i]),VF.mul(f,full[i])),
                VF.add(VF.mul(p,partialState[i]),VF.mul(copy,state[i])));
            acc=VF.add(VF.mul(acc,c.alpha),VF.mul(transition,VF.sub(VF.mul(active,b.evaluations[64+i]),expected)));
        }
        for(uint256 i;i<10;++i)acc=VF.add(VF.mul(acc,c.alpha),VF.mul(init,VF.sub(state[14+i],VP.capacity(i))));
        for(uint256 i;i<12;++i)acc=VF.add(VF.mul(acc,c.alpha),VF.mul(lastSel,VF.sub(state[i],b.outputs[i])));
        for(uint256 i;i<16;++i){
            uint256 requestLimb=uint8(request[2*i])+(uint256(uint8(request[2*i+1]))<<8);
            acc=VF.add(VF.mul(acc,c.alpha),VF.sub(b.evaluations[40+i],VF.scalar(requestLimb)));
        }
        uint256 quotient;
        uint256[8] memory zs;
        for(uint256 i;i<8;++i){
            uint256 shifted=VF.scale(z,VF.basePow(VP.quotientShift(i),P-2));
            zs[i]=VF.sub(VF.pow2(shifted,7),ONE);
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
    function combination(uint256[268] memory powers,bytes calldata row,uint256 at,uint256 start,uint256 width) internal pure returns(uint256 r) {
        // Every row word has already passed the Merkle field checks. At most
        // 48 reduced products are accumulated per lane, below 2^68. Applying
        // the Montgomery factor afterwards stays below 2^99.
        assembly("memory-safe") {
            let a0:=0 let a1:=0 let a2:=0 let a3:=0
            let a4:=0 let a5:=0 let a6:=0 let a7:=0
            let pp:=add(powers,mul(start,32))
            let rp:=add(row.offset,mul(at,4))
            for {let i:=0} lt(i,width) {i:=add(i,1)} {
                let power:=mload(add(pp,mul(i,32)))
                let word:=shr(224,calldataload(add(rp,mul(i,4))))
                let v:=or(or(shl(24,and(word,255)),shl(8,and(word,0xff00))),or(and(shr(8,word),0xff00),shr(24,word)))
                a0:=add(a0,mul(and(power,0xffffffff),v))
                a1:=add(a1,mul(and(shr(32,power),0xffffffff),v))
                a2:=add(a2,mul(and(shr(64,power),0xffffffff),v))
                a3:=add(a3,mul(and(shr(96,power),0xffffffff),v))
                a4:=add(a4,mul(and(shr(128,power),0xffffffff),v))
                a5:=add(a5,mul(and(shr(160,power),0xffffffff),v))
                a6:=add(a6,mul(and(shr(192,power),0xffffffff),v))
                a7:=add(a7,mul(and(shr(224,power),0xffffffff),v))
            }
            r:=mod(mul(a0,1057030144),2130706433)
            r:=or(r,shl(32,mod(mul(a1,1057030144),2130706433)))
            r:=or(r,shl(64,mod(mul(a2,1057030144),2130706433)))
            r:=or(r,shl(96,mod(mul(a3,1057030144),2130706433)))
            r:=or(r,shl(128,mod(mul(a4,1057030144),2130706433)))
            r:=or(r,shl(160,mod(mul(a5,1057030144),2130706433)))
            r:=or(r,shl(192,mod(mul(a6,1057030144),2130706433)))
            r:=or(r,shl(224,mod(mul(a7,1057030144),2130706433)))
        }
    }
    function prepareCache(VBase calldata b,bytes32 request,bytes32 context) external pure returns(QueryCache memory cache) {
        Challenges memory c=transcript(b,request,context);require(checkOuterWithChallenges(b,request,c),"outer");cache.challenges=c;cache.powers[0]=ONE;
        for(uint256 i=1;i<268;++i)cache.powers[i]=VF.mul(cache.powers[i-1],c.pcsAlpha);
        uint256[12] memory atZ;uint256[12] memory offsets=[uint256(0),16,64,112,128,144,160,176,192,208,224,240];
        for(uint256 point;point<12;++point){uint256 width=point==1||point==2?48:point==11?28:16;
            for(uint256 i;i<width;++i)atZ[point]=VF.add(atZ[point],VF.mul(cache.powers[offsets[point]+i],b.evaluations[offsets[point]+i]));
        }
        cache.atZ=atZ;
    }
    // The calling vault authenticates this cache against the hash returned
    // by prepareCache for the exact immutable base and request of its job.
    function checkQueries(VBase calldata b,uint256 start,VQuery[] calldata queries,QueryCache calldata authenticatedCache) external pure returns(bool) {
        require(queries.length>0&&queries.length<=12&&start+queries.length<=64,"query range");
        QueryCache memory cache=authenticatedCache;
        for(uint256 q;q<queries.length;++q)checkQuery(b,cache.challenges,queries[q],cache.challenges.indices[start+q],cache.powers,cache.atZ);
        return true;
    }
    function checkQuery(VBase calldata b,Challenges memory c,VQuery calldata q,uint256 index,
        uint256[268] memory powers,uint256[12] memory atZ) internal pure {
        uint256 salt=VP.MERKLE_SALT_WORDS;
        uint256[4] memory leafLengths=[uint256((16+salt)*4),(48+salt)*4,8*(16+salt)*4,(28+salt)*4];
        for(uint256 i;i<4;++i){require(q.leaves[i].length==leafLengths[i],"input length");
            bytes memory root=i==3?VP.preprocessedRoot():b.roots[i];merkle(q.leaves[i],q.paths[i],index,12,root);
        }
        uint256 x=VF.baseMul(VP.FIELD_GENERATOR,VF.basePow(VP.generator(12),reverse(index,12)));
        uint256 inverse=VF.inverse(VF.sub(c.zeta,x),q.inverses[0]);
        uint256 inverseNext=VF.inverse(VF.sub(VF.scale(c.zeta,VP.generator(6)),x),q.inverses[1]);
        uint256 reduced=VF.mul(VF.sub(atZ[0],combination(powers,q.leaves[0],0,0,16)),inverse);
        reduced=VF.add(reduced,VF.mul(VF.sub(atZ[1],combination(powers,q.leaves[1],0,16,48)),inverse));
        reduced=VF.add(reduced,VF.mul(VF.sub(atZ[2],combination(powers,q.leaves[1],0,64,48)),inverseNext));
        for(uint256 m;m<8;++m)reduced=VF.add(reduced,VF.mul(VF.sub(atZ[3+m],
            combination(powers,q.leaves[2],(16+salt)*m,112+16*m,16)),inverse));
        reduced=VF.add(reduced,VF.mul(VF.sub(atZ[11],combination(powers,q.leaves[3],0,240,28)),inverse));
        uint256 logHeight=12;
        for(uint256 round;round<4;++round){
            uint256 logArity=2;uint256 arity=1<<logArity;
            require(q.leaves[4+round].length==arity*32+salt*4,"FRI length");
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

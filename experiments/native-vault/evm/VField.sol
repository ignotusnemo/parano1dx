// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

// Eight KoalaBear coefficients in 32-bit lanes, using the exact Montgomery
// representation of the pinned native verifier. The extension is X^8 - 3.
library VF {
    uint256 internal constant P=2130706433;
    uint256 internal constant ONE=33554430;
    uint256 internal constant RI=1057030144;
    function valid(uint256 a) internal pure returns(bool) {
        for(uint256 i;i<8;++i) if(uint32(a>>(32*i))>=P) return false;
        return true;
    }
    function scalar(uint256 a) internal pure returns(uint256) {return mulmod(a,ONE,P);}
    function canonical(uint256 a) internal pure returns(uint256) {return mulmod(a,RI,P);}
    function baseMul(uint256 a,uint256 b) internal pure returns(uint256) {return mulmod(mulmod(a,b,P),RI,P);}
    function basePow(uint256 a,uint256 n) internal pure returns(uint256 r) {
        r=ONE;while(n!=0){if(n&1!=0)r=baseMul(r,a);a=baseMul(a,a);n>>=1;}
    }
    function add(uint256 a,uint256 b) internal pure returns(uint256 r) {
        assembly("memory-safe") {
            let v:=add(a,b)
            for {let i:=0} lt(i,256) {i:=add(i,32)} {
                let x:=and(shr(i,v),0xffffffff)
                if iszero(lt(x,2130706433)){x:=sub(x,2130706433)}
                r:=or(r,shl(i,x))
            }
        }
    }
    function sub(uint256 a,uint256 b) internal pure returns(uint256 r) {
        assembly("memory-safe") {
            for {let i:=0} lt(i,256) {i:=add(i,32)} {
                let x:=sub(add(and(shr(i,a),0xffffffff),2130706433),and(shr(i,b),0xffffffff))
                if iszero(lt(x,2130706433)){x:=sub(x,2130706433)}
                r:=or(r,shl(i,x))
            }
        }
    }
    function scale(uint256 a,uint256 b) internal pure returns(uint256 r) {
        uint256 coefficient=mulmod(b,RI,P);
        assembly("memory-safe") {
            for {let i:=0} lt(i,256) {i:=add(i,32)} {
                r:=or(r,shl(i,mod(mul(and(shr(i,a),0xffffffff),coefficient),2130706433)))
            }
        }
    }
    function mul(uint256 a,uint256 b) internal pure returns(uint256 r) {
        uint256 inverse=RI;
        assembly("memory-safe") {
            r:=or(r,shl(0,mod(mul(add(add(add(add(add(add(add(mul(and(shr(0,a),0xffffffff),and(shr(0,b),0xffffffff)),mul(mul(and(shr(32,a),0xffffffff),and(shr(224,b),0xffffffff)),3)),mul(mul(and(shr(64,a),0xffffffff),and(shr(192,b),0xffffffff)),3)),mul(mul(and(shr(96,a),0xffffffff),and(shr(160,b),0xffffffff)),3)),mul(mul(and(shr(128,a),0xffffffff),and(shr(128,b),0xffffffff)),3)),mul(mul(and(shr(160,a),0xffffffff),and(shr(96,b),0xffffffff)),3)),mul(mul(and(shr(192,a),0xffffffff),and(shr(64,b),0xffffffff)),3)),mul(mul(and(shr(224,a),0xffffffff),and(shr(32,b),0xffffffff)),3)),inverse),2130706433)))
            r:=or(r,shl(32,mod(mul(add(add(add(add(add(add(add(mul(and(shr(0,a),0xffffffff),and(shr(32,b),0xffffffff)),mul(and(shr(32,a),0xffffffff),and(shr(0,b),0xffffffff))),mul(mul(and(shr(64,a),0xffffffff),and(shr(224,b),0xffffffff)),3)),mul(mul(and(shr(96,a),0xffffffff),and(shr(192,b),0xffffffff)),3)),mul(mul(and(shr(128,a),0xffffffff),and(shr(160,b),0xffffffff)),3)),mul(mul(and(shr(160,a),0xffffffff),and(shr(128,b),0xffffffff)),3)),mul(mul(and(shr(192,a),0xffffffff),and(shr(96,b),0xffffffff)),3)),mul(mul(and(shr(224,a),0xffffffff),and(shr(64,b),0xffffffff)),3)),inverse),2130706433)))
            r:=or(r,shl(64,mod(mul(add(add(add(add(add(add(add(mul(and(shr(0,a),0xffffffff),and(shr(64,b),0xffffffff)),mul(and(shr(32,a),0xffffffff),and(shr(32,b),0xffffffff))),mul(and(shr(64,a),0xffffffff),and(shr(0,b),0xffffffff))),mul(mul(and(shr(96,a),0xffffffff),and(shr(224,b),0xffffffff)),3)),mul(mul(and(shr(128,a),0xffffffff),and(shr(192,b),0xffffffff)),3)),mul(mul(and(shr(160,a),0xffffffff),and(shr(160,b),0xffffffff)),3)),mul(mul(and(shr(192,a),0xffffffff),and(shr(128,b),0xffffffff)),3)),mul(mul(and(shr(224,a),0xffffffff),and(shr(96,b),0xffffffff)),3)),inverse),2130706433)))
            r:=or(r,shl(96,mod(mul(add(add(add(add(add(add(add(mul(and(shr(0,a),0xffffffff),and(shr(96,b),0xffffffff)),mul(and(shr(32,a),0xffffffff),and(shr(64,b),0xffffffff))),mul(and(shr(64,a),0xffffffff),and(shr(32,b),0xffffffff))),mul(and(shr(96,a),0xffffffff),and(shr(0,b),0xffffffff))),mul(mul(and(shr(128,a),0xffffffff),and(shr(224,b),0xffffffff)),3)),mul(mul(and(shr(160,a),0xffffffff),and(shr(192,b),0xffffffff)),3)),mul(mul(and(shr(192,a),0xffffffff),and(shr(160,b),0xffffffff)),3)),mul(mul(and(shr(224,a),0xffffffff),and(shr(128,b),0xffffffff)),3)),inverse),2130706433)))
            r:=or(r,shl(128,mod(mul(add(add(add(add(add(add(add(mul(and(shr(0,a),0xffffffff),and(shr(128,b),0xffffffff)),mul(and(shr(32,a),0xffffffff),and(shr(96,b),0xffffffff))),mul(and(shr(64,a),0xffffffff),and(shr(64,b),0xffffffff))),mul(and(shr(96,a),0xffffffff),and(shr(32,b),0xffffffff))),mul(and(shr(128,a),0xffffffff),and(shr(0,b),0xffffffff))),mul(mul(and(shr(160,a),0xffffffff),and(shr(224,b),0xffffffff)),3)),mul(mul(and(shr(192,a),0xffffffff),and(shr(192,b),0xffffffff)),3)),mul(mul(and(shr(224,a),0xffffffff),and(shr(160,b),0xffffffff)),3)),inverse),2130706433)))
            r:=or(r,shl(160,mod(mul(add(add(add(add(add(add(add(mul(and(shr(0,a),0xffffffff),and(shr(160,b),0xffffffff)),mul(and(shr(32,a),0xffffffff),and(shr(128,b),0xffffffff))),mul(and(shr(64,a),0xffffffff),and(shr(96,b),0xffffffff))),mul(and(shr(96,a),0xffffffff),and(shr(64,b),0xffffffff))),mul(and(shr(128,a),0xffffffff),and(shr(32,b),0xffffffff))),mul(and(shr(160,a),0xffffffff),and(shr(0,b),0xffffffff))),mul(mul(and(shr(192,a),0xffffffff),and(shr(224,b),0xffffffff)),3)),mul(mul(and(shr(224,a),0xffffffff),and(shr(192,b),0xffffffff)),3)),inverse),2130706433)))
            r:=or(r,shl(192,mod(mul(add(add(add(add(add(add(add(mul(and(shr(0,a),0xffffffff),and(shr(192,b),0xffffffff)),mul(and(shr(32,a),0xffffffff),and(shr(160,b),0xffffffff))),mul(and(shr(64,a),0xffffffff),and(shr(128,b),0xffffffff))),mul(and(shr(96,a),0xffffffff),and(shr(96,b),0xffffffff))),mul(and(shr(128,a),0xffffffff),and(shr(64,b),0xffffffff))),mul(and(shr(160,a),0xffffffff),and(shr(32,b),0xffffffff))),mul(and(shr(192,a),0xffffffff),and(shr(0,b),0xffffffff))),mul(mul(and(shr(224,a),0xffffffff),and(shr(224,b),0xffffffff)),3)),inverse),2130706433)))
            r:=or(r,shl(224,mod(mul(add(add(add(add(add(add(add(mul(and(shr(0,a),0xffffffff),and(shr(224,b),0xffffffff)),mul(and(shr(32,a),0xffffffff),and(shr(192,b),0xffffffff))),mul(and(shr(64,a),0xffffffff),and(shr(160,b),0xffffffff))),mul(and(shr(96,a),0xffffffff),and(shr(128,b),0xffffffff))),mul(and(shr(128,a),0xffffffff),and(shr(96,b),0xffffffff))),mul(and(shr(160,a),0xffffffff),and(shr(64,b),0xffffffff))),mul(and(shr(192,a),0xffffffff),and(shr(32,b),0xffffffff))),mul(and(shr(224,a),0xffffffff),and(shr(0,b),0xffffffff))),inverse),2130706433)))
        }
    }
    function pow2(uint256 a,uint256 n) internal pure returns(uint256) {
        for(uint256 i;i<n;++i)a=mul(a,a);return a;
    }
    function inverse(uint256 a,uint256 witness) internal pure returns(uint256) {
        require(valid(witness)&&mul(a,witness)==ONE,"inverse");return witness;
    }
    function cube(uint256 a) internal pure returns(uint256){return mul(mul(a,a),a);}
    function le32(uint256 a) internal pure returns(bytes memory out) {
        out=new bytes(4);for(uint256 i;i<4;++i)out[i]=bytes1(uint8(a>>(8*i)));
    }
    function reverseBytes(uint256 x) internal pure returns(uint256 r) {
        assembly("memory-safe") {
            x:=or(shl(8,and(x,0x00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff)),and(shr(8,x),0x00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff))
            x:=or(shl(16,and(x,0x0000ffff0000ffff0000ffff0000ffff0000ffff0000ffff0000ffff0000ffff)),and(shr(16,x),0x0000ffff0000ffff0000ffff0000ffff0000ffff0000ffff0000ffff0000ffff))
            x:=or(shl(32,and(x,0x00000000ffffffff00000000ffffffff00000000ffffffff00000000ffffffff)),and(shr(32,x),0x00000000ffffffff00000000ffffffff00000000ffffffff00000000ffffffff))
            x:=or(shl(64,and(x,0x0000000000000000ffffffffffffffff0000000000000000ffffffffffffffff)),and(shr(64,x),0x0000000000000000ffffffffffffffff0000000000000000ffffffffffffffff))
            r:=or(shl(128,x),shr(128,x))
        }
    }
    function le256(uint256 a) internal pure returns(bytes memory out) {
        out=new bytes(32);uint256 r=reverseBytes(a);
        assembly("memory-safe"){mstore(add(out,32),r)}
    }
}

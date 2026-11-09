// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

library VS {
    struct Wide {uint256 hi;uint256 lo;}
    function greater(Wide memory a,Wide memory b) internal pure returns(bool){return a.hi>b.hi||(a.hi==b.hi&&a.lo>b.lo);}
    function subtract(Wide memory a,Wide memory b) internal pure {unchecked{a.hi-=b.hi+(a.lo<b.lo?1:0);a.lo-=b.lo;}}
    function multiply(Wide memory a,uint256 b) internal pure {
        unchecked{uint256 carry;uint256 low;uint256 v=a.lo;
            assembly("memory-safe"){let mm:=mulmod(v,b,not(0)) low:=mul(v,b) carry:=sub(sub(mm,low),lt(mm,low))}
            a.lo=low;a.hi=a.hi*b+carry;
        }
    }
    function divide(Wide memory a,uint256 b) internal pure returns(uint256 rem){
        uint256 mask=type(uint128).max;uint256 x=a.hi>>128;uint256 q0=x/b;rem=x%b;
        x=(rem<<128)|(a.hi&mask);uint256 q1=x/b;rem=x%b;
        x=(rem<<128)|(a.lo>>128);uint256 q2=x/b;rem=x%b;
        x=(rem<<128)|(a.lo&mask);uint256 q3=x/b;rem=x%b;
        a.hi=(q0<<128)|q1;a.lo=(q2<<128)|q3;
    }
    function modulus() internal pure returns(Wide memory){return Wide(MODHI,MODLO);}
    uint256 constant MODHI=64427802546609629243841863991856784172706616784736828481322398661;
    uint256 constant MODLO=17668528060716580920043826700417417597277364823354351168605906108221497745344;
    function positions(Wide memory state) internal pure returns(uint256[64] memory out){
        Wide memory m=modulus();Wide memory rank=Wide(0,0);
        state.lo=(state.lo>>12)|(state.hi<<244);state.hi>>=12;
        for(uint256 bit=500;bit>0;){unchecked{--bit;rank.hi=(rank.hi<<1)|(rank.lo>>255);rank.lo<<=1;}
            uint256 digit=bit>=256?(state.hi>>(bit-256))&1:(state.lo>>bit)&1;rank.lo|=digit;
            if(!greater(m,rank))subtract(rank,m);
        }
        Wide memory c=Wide(m.hi,m.lo);multiply(c,4032);require(divide(c,4096)==0,"binomial");uint256 n=4095;
        for(uint256 k=64;k>0;--k){
            while(greater(c,rank)){multiply(c,n-k);require(divide(c,n)==0,"binomial");--n;}
            out[k-1]=n;subtract(rank,c);
            if(k>1){multiply(c,k);require(divide(c,n)==0,"binomial");--n;}
        }
        require(rank.hi==0&&rank.lo==0,"subset rank");
    }
}

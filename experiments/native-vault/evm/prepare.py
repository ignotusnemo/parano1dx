"""Translate a native proof to independently authenticated query paths.

All proof values are public. This tool never loads a wallet secret.
"""
from pathlib import Path
import hashlib,json,struct,sys
from math import comb
from Crypto.Hash import keccak

HERE=Path(__file__).resolve().parent
RESULTS=Path(sys.argv[1]).resolve() if len(sys.argv)>1 else HERE.parent/'results'/'evm'
P=2130706433
ONE=pow(2,32,P)
RI=pow(ONE,-1,P)
MASK=(1<<32)-1
def kh(x):
    k=keccak.new(digest_bits=256);k.update(x);return k.digest()
def hybrid(x):return hashlib.sha256(x).digest()+kh(x)
def raw(x):return x*ONE%P
def pack(xs):return sum(x<<(32*i) for i,x in enumerate(xs))
def unpack(x):return [(x>>(32*i))&MASK for i in range(8)]
def add(a,b):return pack([(x+y)%P for x,y in zip(unpack(a),unpack(b))])
def sub(a,b):return pack([(x-y)%P for x,y in zip(unpack(a),unpack(b))])
def mul(a,b):
    x=unpack(a);y=unpack(b)
    return pack([sum(x[j]*y[(i-j)%8]*(3 if j>i else 1) for j in range(8))*RI%P for i in range(8)])
def scale(a,b):return pack([x*b*RI%P for x in unpack(a)])
def epow(a,n):
    out=ONE
    while n:
        if n&1:out=mul(out,a)
        a=mul(a,a);n>>=1
    return out
def inv(a):
    result=epow(a,P**8-2);assert mul(a,result)==ONE;return result
def bpow(a,n):return raw(pow(a*RI%P,n,P))
def fieldbytes(xs):return b''.join(struct.pack('<I',x) for x in xs)
def root(cap):return b''.join(struct.pack('<Q',x)for x in cap['cap'][0])
def canonical_ext(x):
    if isinstance(x,dict):x=x['value']
    return pack(x)

class Challenger:
    def __init__(self,domain):
        self.input=domain;self.output=b''
    def observe(self,x):self.input+=x;self.output=b''
    def byte(self):
        if not self.output:self.output=hybrid(self.input);self.input=self.output
        v=self.output[-1];self.output=self.output[:-1];return v
    def word(self):return sum(self.byte()<<(8*i) for i in range(4))
    def ext(self):
        n=int.from_bytes(bytes(self.byte() for _ in range(64)),'little');v=[]
        for _ in range(8):n,r=divmod(n,P);v.append(raw(r))
        return pack(v)

def subset(n):
    rank=n%comb(4096,64);out=[0]*64;at=4095;c=comb(at,64)
    for k in range(64,0,-1):
        while c>rank:c=c*(at-k)//at;at-=1
        out[k-1]=at;rank-=c
        if k>1:c=c*k//at;at-=1
    assert rank==0 and len(set(out))==64
    return out

def paths(indices,leaves,siblings,height,expected):
    nodes={};front={};it=iter(siblings);used=0
    for index,leaf in zip(indices,leaves):
        digest=hybrid(b'Parano1dX/leaf'+leaf)
        if index in front:assert front[index]==digest
        front[index]=digest;nodes[0,index]=digest
    for level in range(height):
        parents={}
        for parent in sorted(set(i//2 for i in front)):
            children=[]
            for child in [2*parent,2*parent+1]:
                if child in front:digest=front[child]
                else:digest=next(it);used+=1;nodes[level,child]=digest
                children.append(digest)
            digest=hybrid(b'Parano1dX/node'+b''.join(children))
            parents[parent]=digest;nodes[level+1,parent]=digest
        front=parents
    assert next(it,None) is None and front=={0:expected},'Merkle correspondence'
    return [b''.join(nodes[l,(i>>l)^1]for l in range(height)) for i in indices]

def generate():
    x=json.loads((RESULTS/'evm-export.json').read_text());p=x['proof'];f=p['opening_proof'][1]
    profile=x['profile'];salt=profile['merkle_salt_words'];grinding=profile['query_grinding_bits']
    assert salt==20 and grinding==12
    claims=[pack(v)for r in x['claims_raw']for m in r for point in m for v in point]
    assert len(claims)==268
    roots=[root(p['commitments'][k])for k in ['random','trace','quotient_chunks']]
    roots.extend(root(c)for c in f['commit_phase_commits'])
    c=Challenger(profile['parameter_domain'].encode()+bytes(x['request_context']));c.observe(bytes.fromhex(x['seeds']['stark']));c.observe(roots[1]);c.observe(bytes.fromhex(x['preprocessed_cap']))
    c.observe(fieldbytes(x['public_raw']));alpha=c.ext()
    c.observe(roots[2]);c.observe(roots[0]);zeta=c.ext()
    c.observe(bytes.fromhex(x['seeds']['pcs']));c.observe(b''.join(v.to_bytes(32,'little')for v in claims));pa=c.ext()
    c.observe(bytes.fromhex(x['seeds']['fri']));betas=[]
    for r in roots[3:]:c.observe(r);betas.append(c.ext())
    final=canonical_ext(f['final_poly'][0]);c.observe(final.to_bytes(32,'little'))
    c.byte();seal=c.input;pow_witness=x['query_pow_witness_raw'];assert 0<=pow_witness<P
    bad_pow=next(candidate for candidate in range(32)
        if int.from_bytes(hybrid(seal+struct.pack('<I',candidate))[-4:],'big')&((1<<grinding)-1))
    c.observe(struct.pack('<I',pow_witness));qstate=int.from_bytes(bytes(c.byte() for _ in range(64)),'little')
    assert qstate&((1<<grinding)-1)==0
    indices=subset(qstate>>grinding)
    ref=x['transcript']
    assert alpha==pack(ref['alpha']) and zeta==pack(ref['zeta']) and pa==pack(ref['pcs_alpha'])
    assert betas==[pack(v)for v in ref['betas']] and indices==ref['indices'],'transcript correspondence'
    query=[{'leaves':[],'paths':[]}for _ in range(64)]
    all_roots=roots[:3]+[bytes.fromhex(x['preprocessed_cap'])]+roots[3:]
    for batch,o in enumerate(f['input_openings']):
        leaves=[fieldbytes([v for row,salt in zip(rows,salts) for v in row+salt])
            for rows,salts in zip(o['opened_values'],o['opening_proof'][0])]
        siblings=[b''.join(struct.pack('<Q',v)for v in d)for d in o['opening_proof'][1]['sibling_hashes']]
        ps=paths(indices,leaves,siblings,12,all_roots[batch])
        for q,leaf,path in zip(query,leaves,ps):q['leaves'].append('0x'+leaf.hex());q['paths'].append('0x'+path.hex())
    cumulative=0
    for r,(o,arity_log) in enumerate(zip(f['commit_phase_openings'],[2,2,2,2])):
        cumulative+=arity_log
        ix=[i>>cumulative for i in indices]
        leaves=[fieldbytes([v for ext in values for v in ext]+salt[0])
            for values,salt in zip(x['hints_raw'][r],o['opening_proof'][0])]
        siblings=[b''.join(struct.pack('<Q',v)for v in d)for d in o['opening_proof'][1]['sibling_hashes']]
        ps=paths(ix,leaves,siblings,12-cumulative,all_roots[4+r])
        for q,leaf,path in zip(query,leaves,ps):q['leaves'].append('0x'+leaf.hex());q['paths'].append('0x'+path.hex())
    for qi,(i,q) in enumerate(zip(indices,query)):
        rev=int(f'{i:012b}'[::-1],2)
        point=x['field_generator_raw']*bpow(x['generators_raw'][12],rev)*RI%P
        if 'query_inverse_hints_raw' in x:
            inverses=[pack(v) for v in x['query_inverse_hints_raw'][qi]]
            assert mul(sub(zeta,point),inverses[0])==ONE
            assert mul(sub(scale(zeta,x['generators_raw'][6]),point),inverses[1])==ONE
        else:
            inverses=[inv(sub(zeta,point)),inv(sub(scale(zeta,x['generators_raw'][6]),point))]
        q['inverses']=[hex(v) for v in inverses]
    zh=sub(epow(zeta,128),ONE);last=bpow(x['generators_raw'][7],127)
    outer_denominators=[sub(zeta,ONE),sub(zeta,last),zh]
    outer_inv=[pack(v) for v in x['outer_inverse_hints_raw']] if 'outer_inverse_hints_raw' in x else [inv(v) for v in outer_denominators]
    assert all(mul(d,v)==ONE for d,v in zip(outer_denominators,outer_inv))
    base={'evaluations':[hex(v)for v in claims],'roots':['0x'+r.hex()for r in roots],
          'finalPolynomial':hex(final),'outputs':x['public_raw'][:12],'outerInverses':[hex(v)for v in outer_inv],
          'queryPowWitness':pow_witness,'queryIndices':'0x'+b''.join(struct.pack('<H',i) for i in indices).hex()}
    fixture={'base':base,'queries':query,'invalid_query_pow_witness':bad_pow,
        'request_id':bytes(json.loads((RESULTS/'native-proof.json').read_text())['request_id']).hex(),
        'reference':{'alpha':hex(alpha),'zeta':hex(zeta),'pcsAlpha':hex(pa),'betas':[hex(b)for b in betas],'indices':indices}}
    (RESULTS/'evm-fixture.json').write_text(json.dumps(fixture)+'\n')
    # The streaming Solana transport carries this same authenticated base and
    # one ordinary Merkle query at a time. Its constants are profile-specific.
    def ext_bytes(v):return int(v,16).to_bytes(32,'little')
    base_bytes=b''.join(ext_bytes(v) for v in base['evaluations'])+b''.join(roots)+final.to_bytes(32,'little')+fieldbytes(base['outputs'])+b''.join(ext_bytes(v) for v in base['outerInverses'])+bytes.fromhex(base['queryIndices'][2:])+struct.pack('<I',pow_witness)
    assert len(base_bytes)==9332
    (RESULTS/'stream-base.bin').write_bytes(base_bytes)
    leaf_lengths=[(16+salt)*4,(48+salt)*4,8*(16+salt)*4,(28+salt)*4]+[(32+salt)*4]*4
    query_bytes=sum(leaf_lengths)+76*64+64
    previous=bytes(query_bytes)
    previous_query=None;previous_index=None
    item_lengths=leaf_lengths+[64]*76+[32,32]
    for qi,original in enumerate(sorted(range(64),key=lambda i:indices[i])):
        q=query[original]
        payload=b''.join(bytes.fromhex(v[2:]) for v in q['leaves']+q['paths'])+b''.join(ext_bytes(v) for v in q['inverses'])
        assert len(payload)==query_bytes
        (RESULTS/f'stream-query-{qi:02}.bin').write_bytes(payload)
        derived=set();path_item=8
        if previous_query is not None:
            for tree,height in enumerate([12,12,12,12,10,8,6,4]):
                shift=12-height;old=previous_index>>shift;new=indices[original]>>shift
                difference=old^new
                if difference:
                    divergence=difference.bit_length()-1
                    digest=hybrid(b'Parano1dX/leaf'+bytes.fromhex(previous_query['leaves'][tree][2:]))
                    path=bytes.fromhex(previous_query['paths'][tree][2:])
                    for level in range(divergence):
                        sibling=path[64*level:64*(level+1)]
                        digest=hybrid(b'Parano1dX/node'+(sibling+digest if (old>>level)&1 else digest+sibling))
                    expected=bytes.fromhex(q['paths'][tree][2:])[64*divergence:64*(divergence+1)]
                    assert digest==expected,'derived sibling correspondence'
                    derived.add(path_item+divergence)
                path_item+=height
        mask=bytearray(12);literal=bytearray();offset=0
        for item,n in enumerate(item_lengths):
            if item not in derived and payload[offset:offset+n]!=previous[offset:offset+n]:
                mask[item//8]|=1<<(item%8);literal.extend(payload[offset:offset+n])
            offset+=n
        (RESULTS/f'stream-delta-{qi:02}.bin').write_bytes(mask+literal)
        previous=payload
        previous_query=q;previous_index=indices[original]
    if '--rust-parameters' in sys.argv:
        def array(name,values,kind='u8'):
            return f'pub const {name}: [{kind};{len(values)}]=['+','.join(map(str,values))+'];\n'
        rust='// Fixed public parameters generated from the pinned native backend.\n'
        for name,value in x['seeds'].items():rust+=array(name.upper()+'_SEED',bytes.fromhex(value))
        rust+=array('PREPROCESSED_ROOT',bytes.fromhex(x['preprocessed_cap']))
        for name,key in [('GENERATORS','generators_raw'),('QUOTIENT_SHIFTS','quotient_shifts_raw'),('QUOTIENT_DENOMINATORS','quotient_denominator_inverses_raw')]:
            rust+=array(name,[v*RI%P for v in x[key]],'u32')
        (HERE.parent/'auth/src/stream_parameters.rs').write_text(rust)
    def function(name,values):
        return f'function {name}(uint256 i) internal pure returns(uint256) {{ uint256[{len(values)}] memory v=[uint256({values[0]}),'+','.join(map(str,values[1:]))+'];return v[i];}\n'
    out='// SPDX-License-Identifier: MIT\npragma solidity ^0.8.30;\nlibrary VP {\n'
    out+=f'function parameterDomain() internal pure returns(bytes memory) {{return bytes("{profile["parameter_domain"]}");}}\n'
    out+=f'function authorityDomain() internal pure returns(bytes memory) {{return bytes("{profile["authority_domain"]}");}}\n'
    out+=f'uint256 internal constant MERKLE_SALT_WORDS={salt};\nuint256 internal constant QUERY_GRINDING_BITS={grinding};\n'
    for name,seed in x['seeds'].items():out+=f'function {name}Seed() internal pure returns(bytes memory) {{return hex"{seed}";}}\n'
    out+=f'function preprocessedRoot() internal pure returns(bytes memory) {{return hex"{x["preprocessed_cap"]}";}}\n'
    for name,values in [('generator',x['generators_raw']),('capacity',x['capacity_raw']),
                       ('quotientShift',x['quotient_shifts_raw']),('quotientDenominator',x['quotient_denominator_inverses_raw'])]:out+=function(name,values)
    for name in ['external','internal']:
        data=b''.join(v.to_bytes(4,'big')for col in x[f'{name}_matrix_columns_raw']for v in col)
        out+=f'function {name}Matrix() internal pure returns(bytes memory) {{return hex"{data.hex()}";}}\n'
    matrix=x['internal_matrix_columns_raw']
    for col in range(24):
        assert all(matrix[col][row]==ONE for row in range(24) if row!=col)
    out+=function('internalDiagonal',[(matrix[i][i]-ONE)%P for i in range(24)])
    out+=f'uint256 internal constant FIELD_GENERATOR={x["field_generator_raw"]};\n}}\n'
    (HERE/'VParameters.sol').write_text(out)
    print(json.dumps({'native_transcript_matches':True,'Merkle_roots_match':True,
        'query_count':len(query),'base_evaluations':len(claims),'full_path_payload_bytes':sum(sum(len(bytes.fromhex(v[2:]))for v in q['leaves']+q['paths'])for q in query)}))
if __name__=='__main__':generate()

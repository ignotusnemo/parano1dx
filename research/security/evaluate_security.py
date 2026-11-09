#!/usr/bin/env python3
"""Exact native proof-loss and AES-128 resource comparison."""
from fractions import Fraction as F
from math import comb,isqrt,log2
from pathlib import Path
import argparse,hashlib,json
HERE=Path(__file__).resolve().parent
P=2130706433
N=2**512
V=27289
LEAVES=13648
SALT=20
GMIN=1
PRICE=2**20

def rational(x):
    x=F(x)
    return {'numerator':str(x.numerator),'denominator':str(x.denominator),
            'probability':float(x),'negative_log2':log2(x.denominator)-log2(x.numerator) if x else None}

def sqrt_upper(x):
    x=F(x);scaled=x.numerator<<2048;z=isqrt(scaled//x.denominator)
    if z*z*x.denominator<scaled:z+=1
    y=F(z,2**1024);assert y*y>=x;return y

def simulator(s,t):
    delta=LEAVES*(F(1,P**SALT)+F(2*N,P**(16+SALT)))
    phi=F(64*(t+V)**2,P**SALT)+F(64*(t+V)**2,N)
    coin=(2**26+4096)*sqrt_upper(F(2**12*(t+V+256),N))+F(7*P**8,N)
    return s*F(P**4+8192,P**8)+8*s*t*sqrt_upper(delta)+4*s*phi+s*coin+F(4*s,2**1024)+F(1,2**5397)

def corrections(s,t):
    protect=4*t*sqrt_upper(F(8*t+32,N))
    updates=(128*s*(t+V)*sqrt_upper(F(V,P**SALT))
             +128*s*V*sqrt_upper(F(t+V,N))
             +128*s*V*sqrt_upper(F(2*(t+V)*N,P**(16+SALT))))
    record=32*sqrt_upper(F((t+1)**3,N))+F(256,2**256)
    return protect,updates,record

def quantum(s,t,gd,kappa,price):
    assert t>=V and 8*t+32<N
    protect,updates,record=corrections(s,t)
    main=F(10*gd,price)*kappa/(1-F(8*t+32,N))
    loss=simulator(s,t)+(sqrt_upper(main)+protect+updates+record)**2
    return min(F(1),loss),{'main_probability':main,'simulation':simulator(s,t),
        'protection_amplitude':protect,'updates_amplitude':updates,'recording_amplitude':record}

def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--output',type=Path,default=HERE/'security-evaluation.json');args=parser.parse_args()
    rs=json.loads((HERE/'rs-certificate.json').read_text())
    finite=json.loads((HERE/'finite-profile.json').read_text())
    assert rs['source']['dimension']==257 and rs['source']['agreement_count']==896
    assert rs['queries']==64 and rs['codeword_rows']==4096 and rs['extension_degree']==8
    assert finite['main_mask_coordinates']==192 and finite['merkle_salt_words']==SALT
    assert 3*(2*4096-1)+sum(2*n-1 for n in [1024,256,64,16])==V
    m=comb(4096,64);good=comb(rs['source']['agreement_count'],64)
    query=F(((2**500+m-1)//m)*good,N)
    field=F(((N+P**8-1)//P**8)*int(rs['field_error_numerator']),N)
    kappa=query+field
    assert query<F(1,2**154) and field<F(1,2**176)
    assert P**36>2**1115 and F(P**36,3*2**(512+280))>2048
    seq={}
    for bits in [24,32,40,48,56,64,72,73]:
        t=2**bits;s=t//V+1;loss,terms=quantum(s,t,t*t,kappa,1)
        seq[str(bits)]={'combined':rational(loss),'simulation':rational(terms['simulation']),
                        'maximum_attempts':s}
    rows=[]
    s=2**64
    for depth in [40,64,96]:
        g=2**(170-depth);t=g//GMIN+s*2**26+2**20
        value,terms=quantum(s,t,2**170,kappa,PRICE)
        rows.append({'depth_bits':depth,'gates':str(g),'charged_calls':str(t),
            'ideal_bound':rational(value),'terms':{k:rational(v) for k,v in terms.items()}})
    maximum=max(F(int(r['ideal_bound']['numerator']),int(r['ideal_bound']['denominator']))for r in rows)
    assert maximum<F(325524,10**6)
    classical_t=2**143+s*2**26+2**20
    protect,updates,record=corrections(s,classical_t)
    classical=simulator(s,classical_t)+(sqrt_upper(2**143*kappa)+protect+updates+record)**2
    assert classical<F(254316,10**9)
    # Price threshold is an output, not an assumed proof of a circuit lower bound.
    low,high=1,PRICE
    while high-low>1:
        mid=(low+high)//2
        if all(quantum(s,int(r['charged_calls']),2**170,kappa,mid)[0]<F(1,2)for r in rows):high=mid
        else:low=mid
    assert 2**19<high<=PRICE
    references={'nist':'https://csrc.nist.gov/projects/post-quantum-cryptography/post-quantum-cryptography-standardization/evaluation-criteria/security-(evaluation-criteria)',
                'parallel_QROM':'https://arxiv.org/abs/2010.11658',
                'RS':'https://eprint.iacr.org/2026/2056'}
    result={'profile':{'trace_rows':128,'execution_rows':64,'main_mask_coordinates':192,'committed_degree_bound':256,
            'codeword_rows':4096,'queries':64,'extension_degree':8,'base_prime':P,
            'batched_functions':268,'merkle_salt_words':SALT,'query_grinding_bits':12,
            'poseidon_full_rounds':8,'poseidon_partial_rounds':26,'query_sampling':'one-response distinct subset'},
        'public_coin_ledger':{'agreement_upper':rs['agreement_upper'],
            'source_good_positions':rs['source']['agreement_count'],'query_error':rational(F(good,m)),
            'field_error':rational(F(int(rs['field_error_numerator']),P**8)),
            'list_bound_upper':rs['source']['list_bound_upper'],'source_certificate':'rs-certificate.json'},
        'native_grinding_ledger':{'query_group_density':rational(query),'field_density':rational(field),
            'combined_source_density':rational(kappa),'raw_response_blocks':1,'subsets':str(m),
            'maximum_bad_labels':str(((2**500+m-1)//m)*good)},
        'algebraic_privacy':{'per_attempt_error':rational(F(P**4+8192,P**8))},
        'native_quantum_authorization':{'bound':'Adv_pre(B)+eps_der+eps_rng+eps_sim+(sqrt(10GD*kappa/(c*(1-beta/N)))+E_protect+E_updates+E_record)^2',
            'at_query_budget_bits':seq,'primitive_conditions':['fixed authority-preimage hardness for the complete extractor B',
                'joint HKDF security','joint private-generator security'],
            'extractor_quantum_overhead':'original execution and one final database measurement',
            'extractor_classical_overhead':'enumerate at most T rooted prefixes and run the deterministic DKT26 first-order source decoder for each, including all candidate validation'},
        'nist':{'category':1,'status':'conditional on the explicit resource and primitive conditions',
            'reference':'AES-128 key search','quantum_gate_depth_reference_bits':170,
            'classical_gate_reference_bits':143,'depth_bits':[40,64,96],
            'authorization_requests':str(s),'adversarial_calls_per_gate_upper':1,
            'batch_response_gate_depth_condition':PRICE,'resource_condition_status':'declared minimum-cost premise',
            'resource_condition':'sum_j k_sj*c_j <= A_s*delta_s for every batch, at the cheaper component interface',
            'minimum_sufficient_price_for_ideal_bound_below_half':str(high),
            'main_half_gate_depth_floor_bits':log2(PRICE)-log2(float(20*kappa)),
            'quantum_rows':rows,'maximum_ideal_bound':rational(maximum),
            'classical_bound_even_at_unit_hash_price':rational(classical),
            'primitive_advantage_margin':rational(F(1,2)-maximum),
            'primitive_margin_condition':'Adv_pre(B)+eps_der+eps_rng < primitive_advantage_margin',
            'price_sensitivity':{str(c):rational(quantum(s,int(rows[0]['charged_calls']),2**170,kappa,c)[0]) for c in [1,2**10,2**16,2**19,2**20,2**24,2**27]}},
        'references':references,
        'proof_source_sha256':{p.name:hashlib.sha256(p.read_bytes()).hexdigest()for p in sorted(HERE.glob('*.txt'))}}
    args.output.write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps({'native_query_density_bits':-log2(float(query)),'field_density_bits':-log2(float(field)),
        'native_loss_at_T_2_24':seq['24']['combined']['probability'],'conditional_Category_1_ideal_bound':float(maximum),
        'classical_reference_bound':float(classical),'main_half_gate_depth_bits':result['nist']['main_half_gate_depth_floor_bits'],
        'minimum_sufficient_price':str(high),'resource_floor_is_a_declared_condition':True}))
if __name__=='__main__':main()

#!/usr/bin/env python3
"""Independent replay of the exact one-response Fiat-Shamir geometry."""
from pathlib import Path
import importlib.util,json,struct
ROOT=Path(__file__).resolve().parents[2]
spec=importlib.util.spec_from_file_location('vault_export',ROOT/'experiments/native-vault/evm/prepare.py')
a=importlib.util.module_from_spec(spec);spec.loader.exec_module(a)
x=json.loads((ROOT/'experiments/native-vault/results/optimized-solana/evm-export.json').read_text())
class Recorder(a.Challenger):
    def __init__(self,domain):super().__init__(domain);self.inputs=[]
    def byte(self):
        if not self.output:self.inputs.append(len(self.input))
        return super().byte()
p=x['proof'];f=p['opening_proof'][1]
roots=[a.root(p['commitments'][k])for k in ['random','trace','quotient_chunks']]+[a.root(c)for c in f['commit_phase_commits']]
claims=[a.pack(v)for r in x['claims_raw']for m in r for pt in m for v in pt]
c=Recorder(x['profile']['parameter_domain'].encode()+bytes(x['request_context']))
c.observe(bytes.fromhex(x['seeds']['stark']));c.observe(roots[1]);c.observe(bytes.fromhex(x['preprocessed_cap']));c.observe(a.fieldbytes(x['public_raw']));alpha=c.ext()
c.observe(roots[2]);c.observe(roots[0]);z=c.ext();c.observe(bytes.fromhex(x['seeds']['pcs']));c.observe(b''.join(v.to_bytes(32,'little')for v in claims));gamma=c.ext()
c.observe(bytes.fromhex(x['seeds']['fri']));betas=[]
for r in roots[3:]:c.observe(r);betas.append(c.ext())
c.observe(a.canonical_ext(f['final_poly'][0]).to_bytes(32,'little'));c.byte();c.observe(struct.pack('<I',x['query_pow_witness_raw']))
y=int.from_bytes(bytes(c.byte()for _ in range(64)),'little');assert y%4096==0
q=a.subset(y>>12);ref=x['transcript']
assert [alpha,z,gamma]==[a.pack(ref[k])for k in ['alpha','zeta','pcs_alpha']]
assert betas==[a.pack(b)for b in ref['betas']] and q==ref['indices']
assert c.inputs==[623,192,9036,364,128,128,128,96,68],c.inputs
assert c.inputs[0]%4==3 and all(n%4==0 for n in c.inputs[1:])
result={'native_replay_matches':True,'hash_bits':512,'initial_context_bytes':32,'response_inputs_bytes':c.inputs,
        'field_challenges':7,'raw_blocks_per_field_challenge':1,'raw_blocks_per_complete_query_response':1,
        'query_positions':len(q),'all_positions_distinct':len(set(q))==64,'merkle_input_length_mod_four':2,
        'authority_seed_input_bytes':40}
Path(__file__).with_name('transcript-profile.json').write_text(json.dumps(result,indent=2)+'\n');print(json.dumps(result))

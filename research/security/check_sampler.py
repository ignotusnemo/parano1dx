#!/usr/bin/env python3
"""Independent integer checks of radix-p sampling and subset ranking."""
from pathlib import Path
from math import comb
import hashlib,json
ROOT=Path(__file__).resolve().parents[2]
p=ROOT/'experiments/native-vault/results/profile-optimization/sampler-vectors.json'
rows=json.loads(p.read_text());assert len(rows)==128
for row in rows:
    n=int.from_bytes(bytes(row['bytes']),'little');positions=row['positions']
    assert len(positions)==64 and all(0<=x<4096 for x in positions)
    assert all(a<b for a,b in zip(positions,positions[1:]))
    rank=sum(comb(x,i+1) if x>=i+1 else 0 for i,x in enumerate(positions))
    assert rank==(n>>12)%comb(4096,64)
    for digit in row['field_digits']:
        n,r=divmod(n,2130706433);assert digit==r
result={'independent_vectors_checked':len(rows),'subset_rank_checked':True,'radix_field_mapping_checked':True,
        'sample_sha256':hashlib.sha256(p.read_bytes()).hexdigest()}
Path(__file__).with_name('sampler-checks.json').write_text(json.dumps(result,indent=2)+'\n')
print(json.dumps(result))

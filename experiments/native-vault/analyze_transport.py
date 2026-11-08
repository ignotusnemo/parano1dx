"""Exact byte accounting for the existing proof and lossless transport options.

The global frontier total deduplicates leaves and uses the native minimal
Merkle frontier. It is a format estimate, separate from executable transports.
"""
from pathlib import Path
import json,math,struct,sys

case=Path(sys.argv[1]);target=Path(sys.argv[2]) if len(sys.argv)>2 else case/'transport-analysis.json'
x=json.loads((case/'evm-export.json').read_text())
fixture=json.loads((case/'evm-fixture.json').read_text())
fri=x['proof']['opening_proof'][1]
indices=fixture['reference']['indices']
leaf_lengths=[104,232,832,148,168,168,168,168,104]
heights=[12,12,12,12,10,8,6,4,3]
names=['random','trace','quotient','public_preprocessing','fri_1','fri_2','fri_3','fri_4','fri_5']
current={name:0 for name in ['leaf_literals','sibling_literals','inverse_literals','delta_bitmaps','batch_framing','base']}
current['base']=len((case/'stream-base.bin').read_bytes());current['batch_framing']=13+64*2
for i in range(64):
    delta=(case/f'stream-delta-{i:02}.bin').read_bytes();current['delta_bitmaps']+=12
    lengths=leaf_lengths+[64]*sum(heights)+[32,32]
    for item,length in enumerate(lengths):
        if delta[item//8]&(1<<(item%8)):
            current['leaf_literals' if item<9 else 'sibling_literals' if item<88 else 'inverse_literals']+=length
assert sum(current.values())==current['base']+sum((case/f'stream-delta-{i:02}.bin').stat().st_size for i in range(64))+141
trees=[]
for tree in range(9):
    opening=fri['input_openings'][tree] if tree<4 else fri['commit_phase_openings'][tree-4]
    shift=0 if tree<4 else 12-heights[tree]
    unique={}
    for index,q in zip(indices,fixture['queries']):
        row=index>>shift;leaf=q['leaves'][tree];assert row not in unique or unique[row]==leaf
        unique[row]=leaf
    leaves=sum((len(leaf)-2)//2 for leaf in unique.values())
    siblings=len(opening['opening_proof'][1]['sibling_hashes'])*64
    # Independently count the frontier required to connect these rows to root.
    front=set(unique);nodes=0
    for _ in range(heights[tree]):
        nodes+=sum((i^1) not in front for i in front);front={i//2 for i in front}
    assert front=={0} and nodes*64==siblings
    trees.append({'tree':names[tree],'unique_leaves':len(unique),'leaf_bytes':leaves,
        'authentication_frontier_nodes':nodes,'authentication_frontier_bytes':siblings,'total_bytes':leaves+siblings})
global_bytes=current['base']+sum(t['total_bytes'] for t in trees)+len(set(indices))*64
public_preprocessing=trees[3]['total_bytes']
base_packets=sum(math.ceil(len(data)/3584) for data in [(case/'stream-base.bin').read_bytes()]+[
    bytes([min(5,64-start)])+b''.join(struct.pack('<H',len(d))+d for d in [(case/f'stream-delta-{i:02}.bin').read_bytes() for i in range(start,min(64,start+5))])
    for start in range(0,64,5)])
result={'profile':'KoalaBear, extension 8, 64 queries, blowup 8, hybrid 512-bit hashes',
    'current_lossless_delta_bytes':sum(current.values()),'current_components':current,
    'global_frontier_format_estimate_bytes':global_bytes,'global_frontier_trees':trees,
    'public_preprocessing_frontier_bytes':public_preprocessing,
    'global_frontier_with_embedded_preprocessing_estimate_bytes':global_bytes-public_preprocessing,
    'v1_3584_byte_upload_packets':base_packets,
    'v1_eager_transactions_before_retries':base_packets+2,
    'global_frontier_payload_only_transaction_floor':math.ceil(global_bytes/4096),
    'embedded_preprocessing_payload_only_transaction_floor':math.ceil((global_bytes-public_preprocessing)/4096),
    'research_transaction_target':30,
    'scope':'Byte accounting for this fixed proof profile. Frontier totals are prospective lossless encodings, with zero framing overhead. Packet counts exclude retries. Executable transports are measured separately.'}
target.parent.mkdir(parents=True,exist_ok=True);target.write_text(json.dumps(result,indent=2)+'\n')
print(json.dumps(result,indent=2))

"""Render the audited public v1 and Base Sepolia observations."""
from pathlib import Path
import json
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt

root=Path(__file__).resolve().parent
data=json.loads((root/'results/public-network-summary.json').read_text())
assert len(data['solana_devnet'])==2 and 'base_sepolia' in data
normal,fault=data['solana_devnet'];base=data['base_sepolia']
assert normal['transaction_version']==fault['transaction_version']=='v1'
labels=['Solana Devnet\nnormal v1','Solana Devnet\nv1 packet loss','Base Sepolia\nL2 receipts']
values=[normal['confirmed_s'],fault['confirmed_s'],base['confirmed_s']]
plt.rcParams.update({'font.family':'DejaVu Sans','font.size':10,'svg.fonttype':'none','svg.hashsalt':'parano1dx-v1-public'})
fig,ax=plt.subplots(figsize=(8.2,2.8),layout='constrained')
bars=ax.barh(range(3),values,height=.52,color=['#244f84','#91a9c9','#203347'],edgecolor='#203347',linewidth=.6)
bars[1].set_hatch('///')
ax.set_yticks(range(3),labels);ax.invert_yaxis();ax.set_xlim(0,max(values)*1.24)
ax.set_xlabel('Observed complete authorization time (seconds)',labelpad=9)
ax.set_axisbelow(True);ax.xaxis.grid(True,color='#e1e5eb',linewidth=.6)
for spine in ['top','right','left']:ax.spines[spine].set_visible(False)
ax.spines['bottom'].set_color('#b0bac7');ax.tick_params(axis='y',length=0,pad=12)
for bar,value in zip(bars,values):ax.text(value+.35,bar.get_y()+bar.get_height()/2,f'{value:.2f} s',ha='left',va='center',fontweight='bold',color='#172941')
assets=root.parent.parent/'assets';assets.mkdir(exist_ok=True)
fig.savefig(assets/'04-public-v1-latency.svg',metadata={'Date':None,'Creator':'Parano1dX research'})
fig.savefig(assets/'04-public-v1-latency.png',dpi=200,metadata={'Software':'Parano1dX research'})
plt.close(fig)
print(json.dumps({'labels':labels,'seconds':values,'matplotlib':matplotlib.__version__}))

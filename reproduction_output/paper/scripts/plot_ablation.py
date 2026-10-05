from pathlib import Path
import json,csv,statistics,hashlib
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import numpy as np
OUT=Path(__file__).resolve().parents[1]
methods=['PT00','PT01','Union10','Union11']
colors=['#999999','#0072B2','#E69F00','#009E73']
with (OUT/'fig3_ablation_data.csv').open(encoding='utf-8') as f:rows=list(csv.DictReader(f))
for r in rows:
 r['candidate_count']=int(r['candidate_count']);r['median_ms']=float(r['median_ms']);r['latency_relative_to_pt00']=float(r['latency_relative_to_pt00'])
plt.rcParams.update({'font.family':'DejaVu Sans','font.size':9,'axes.titlesize':9,'axes.labelsize':9,'legend.fontsize':8,'pdf.fonttype':42,'axes.spines.top':False,'axes.spines.right':False})
fig,(a,b)=plt.subplots(1,2,figsize=(6.1,2.65),layout='constrained')
values=[[r['latency_relative_to_pt00'] for r in rows if r['layout']=='Same-Branch' and r['candidate_count']==16 and r['method']==m] for m in methods]
assert all(len(v)==30 for v in values)
bp=a.boxplot(values,positions=range(4),widths=.55,showfliers=False,patch_artist=True,medianprops={'color':'black'})
for i,(v,color,box) in enumerate(zip(values,colors,bp['boxes'])):
 box.set_facecolor(color);box.set_alpha(.35)
 a.scatter(i+np.linspace(-.18,.18,len(v)),v,s=9,color=color,alpha=.7,zorder=3)
a.axhline(1,color='#555555',ls='--',lw=.8)
a.set_xticks(range(4),methods,rotation=18)
a.set_ylabel('Latency / PT00 (same instance)')
a.set_title('(a) Same-Branch, C=16 (n=30)')
configs=[('Same-Branch',4),('Same-Branch',16),('Disjoint-Branches',4),('Disjoint-Branches',16)]
x=np.arange(4);width=.19
for j,(m,color) in enumerate(zip(methods,colors)):
 med=[statistics.median(r['median_ms'] for r in rows if r['layout']==l and r['candidate_count']==c and r['method']==m) for l,c in configs]
 b.bar(x+(j-1.5)*width,med,width,color=color,label=m)
b.set_xticks(x,['Same\nC=4','Same\nC=16','Disjoint\nC=4','Disjoint\nC=16'])
b.set_ylim(bottom=0);b.set_ylabel('Authorization latency (ms)');b.set_title('(b) Workload medians (n=30 each)')
b.set_ylim(0,b.get_ylim()[1]*1.25)
b.legend(ncol=2,frameon=False,loc='upper left')
for ext in ['pdf','png']:fig.savefig(OUT/'figures'/('fig3_ablation.'+ext),dpi=350)
plt.close(fig)
print('Recomputed PT00-normalized ablation from 120 discovery raw units; all retained rounds used.')

from __future__ import annotations
import csv,hashlib,json,statistics,sys
from collections import defaultdict
from pathlib import Path
import numpy as np
import matplotlib as mpl
mpl.use('Agg')
import matplotlib.pyplot as plt
HERE=Path(__file__).resolve();EVAL=HERE.parents[1];OUT=EVAL/'results/analysis';DATA=OUT/'data';FIG=OUT/'figures'
METHODS=('PT00','PT01','Union10','Union11'); COLORS={'PT00':'#999999','PT01':'#0072B2','Union10':'#E69F00','Union11':'#009E73'}
def read(stage):return [json.loads(p.read_text(encoding='utf-8')) for p in sorted((EVAL/'results/raw'/stage).glob('*.json'))]
def write_csv(name,rows):
 p=DATA/name;p.parent.mkdir(parents=True,exist_ok=True)
 if not rows:p.write_text('',encoding='utf-8');return
 with p.open('w',newline='',encoding='utf-8') as f:w=csv.DictWriter(f,fieldnames=list(rows[0]));w.writeheader();w.writerows(rows)
def median_rows(d):return {m:statistics.median(r['per_call_ns'] for r in d['timing']['rows'] if r['method']==m)/1e6 for m in d['timing']['medians_ns']}
def bootstrap(rows,reps=10000,seed=20260917):
 by=defaultdict(list)
 for r in rows:by[r['seed']].append(r['speedup'])
 keys=sorted(by);rng=np.random.default_rng(seed);vals=[]
 for _ in range(reps):vals.append(float(np.median([v for k in rng.choice(keys,len(keys),replace=True) for v in by[int(k)]])))
 return float(np.quantile(vals,.025)),float(np.quantile(vals,.975))
def style():
 mpl.rcParams.update({'font.family':'DejaVu Sans','font.size':8,'axes.labelsize':8,'axes.titlesize':8,'legend.fontsize':7,'xtick.labelsize':7,'ytick.labelsize':7,'pdf.fonttype':42,'ps.fonttype':42,'axes.spines.top':False,'axes.spines.right':False})
def save(fig,name):fig.savefig(FIG/f'{name}.pdf',bbox_inches='tight');fig.savefig(FIG/f'{name}.png',dpi=350,bbox_inches='tight');plt.close(fig)
def main():
 DATA.mkdir(parents=True,exist_ok=True);FIG.mkdir(parents=True,exist_ok=True);style();disc,hold,rev,e2e=map(read,('discovery','holdout','revocation','end_to_end'))
 instances=[];rounds=[];ops=[]
 for d in disc+hold:
  c=d['configuration'];med=median_rows(d);base=med['Union11']
  for m,v in med.items():instances.append({'stage':d['stage'],'unit_id':d['unit_id'],'layout':c['layout'],'candidate_count':c['candidate_count'],'seed':c['seed'],'instance':c['instance'],'method':m,'median_ms':v,'ratio_to_union11':v/base,'pt01_union11_speedup':med['PT01']/base})
  for r in d['timing']['rows']:rounds.append({'stage':d['stage'],'unit_id':d['unit_id'],'layout':c['layout'],'candidate_count':c['candidate_count'],'seed':c['seed'],'instance':c['instance'],**r})
  for m,o in d['operations'].items():ops.append({'stage':d['stage'],'unit_id':d['unit_id'],'layout':c['layout'],'candidate_count':c['candidate_count'],'seed':c['seed'],'instance':c['instance'],'method':m,**o['counts'],**o['metrics'],**o['phases_ms']})
 write_csv('instance_latency.csv',instances);write_csv('authorization_rounds.csv',rounds);write_csv('operation_metrics.csv',ops)
 paired=[]
 for d in disc+hold:
  c=d['configuration'];med=median_rows(d);o=d['operations'];paired.append({'stage':d['stage'],'unit_id':d['unit_id'],'layout':c['layout'],'candidate_count':c['candidate_count'],'seed':c['seed'],'instance':c['instance'],'pt01_ms':med['PT01'],'union11_ms':med['Union11'],'speedup':med['PT01']/med['Union11'],'witness_overlap_ratio':o['PT01']['metrics']['witness_overlap_ratio'],'leaf_reduction':1-o['Union11']['counts']['leaf_transforms']/o['PT01']['counts']['leaf_transforms'],'interpolation_reduction':1-o['Union11']['counts']['internal_interpolations']/o['PT01']['counts']['internal_interpolations'],'pairing_reduction':1-o['Union11']['counts']['pairings']/o['PT01']['counts']['pairings']})
 write_csv('paired_speedups.csv',paired)
 summary=[]
 groups=[('discovery','Same-Branch',4),('discovery','Same-Branch',16),('discovery','Disjoint-Branches',4),('discovery','Disjoint-Branches',16),('holdout','Same-Branch',16)]
 for stage,layout,count in groups:
  x=[r for r in paired if r['stage']==stage and r['layout']==layout and r['candidate_count']==count];lo,hi=bootstrap(x)
  summary.append({'stage':stage,'layout':layout,'candidate_count':count,'instances':len(x),'seeds':len({r['seed'] for r in x}),'median_speedup':statistics.median(r['speedup'] for r in x),'ci95_low':lo,'ci95_high':hi})
 write_csv('speedup_summary.csv',summary)
 # Figure 1
 fig,ax=plt.subplots(figsize=(3.35,2.65));y=np.arange(5);vals=[r['median_speedup'] for r in summary];err=np.array([[v-r['ci95_low'] for v,r in zip(vals,summary)],[r['ci95_high']-v for v,r in zip(vals,summary)]])
 ax.errorbar(vals,y,xerr=err,fmt='o',color='#0072B2',ecolor='#333333',capsize=2.5);ax.axvline(1,color='#666',ls='--',lw=.8);ax.axvline(1.2,color='#E69F00',ls=':',lw=.8);ax.axhline(3.5,color='#999',lw=.7)
 ax.set_yticks(y,['Same, C=4','Same, C=16','Disjoint, C=4','Disjoint, C=16','Holdout: Same, C=16']);ax.invert_yaxis();ax.set_xlabel('PT01 / Union11 speedup');ax.set_title('Shared-witness authorization');ax.grid(axis='x',alpha=.2);save(fig,'fig1_primary_speedup')
 # Figure 2
 fig,(a,b)=plt.subplots(2,1,figsize=(3.35,4.7),sharey=True);marks={('Same-Branch',4):'o',('Same-Branch',16):'^',('Disjoint-Branches',4):'s',('Disjoint-Branches',16):'D'}
 for key,mark in marks.items():
  x=[r for r in paired if r['stage']=='discovery' and (r['layout'],r['candidate_count'])==key];label=('Same' if key[0]=='Same-Branch' else 'Disjoint')+f', C={key[1]}'
  a.scatter([r['witness_overlap_ratio'] for r in x],[r['speedup'] for r in x],s=16,marker=mark,alpha=.72,label=label);b.scatter([r['leaf_reduction'] for r in x],[r['speedup'] for r in x],s=16,marker=mark,alpha=.72)
 for ax in (a,b):ax.axhline(1,color='#666',ls='--',lw=.8);ax.grid(alpha=.18)
 a.set_xlabel('Witness overlap ratio');a.set_ylabel('PT01 / Union11 speedup');a.set_title('(a) Structural overlap');a.legend(ncol=2,frameon=False)
 b.set_xlabel('Leaf-transform reduction');b.set_ylabel('PT01 / Union11 speedup');b.set_title('(b) Executed-operation reduction');save(fig,'fig2_overlap_reuse')
 # Figure 3
 fig,(a,b)=plt.subplots(2,1,figsize=(3.35,5.35),constrained_layout=True);positions=np.arange(len(METHODS));norm=[]
 for m in METHODS:norm.append([r['ratio_to_union11'] for r in instances if r['stage']=='discovery' and r['method']==m])
 bp=a.boxplot(norm,positions=positions,widths=.6,showfliers=False,patch_artist=True);[box.set_facecolor(COLORS[m]) for box,m in zip(bp['boxes'],METHODS)];a.axhline(1,color='#333',ls='--',lw=.8);a.set_xticks(positions,METHODS,rotation=18);a.set_ylabel('Latency / Union11');a.set_title('(a) Cache and sharing ablation')
 configs=[('Same-Branch',4),('Same-Branch',16),('Disjoint-Branches',4),('Disjoint-Branches',16)];x=np.arange(4);width=.19
 for j,m in enumerate(METHODS):a2=[statistics.median(r['median_ms'] for r in instances if r['stage']=='discovery' and r['layout']==l and r['candidate_count']==c and r['method']==m) for l,c in configs];b.bar(x+(j-1.5)*width,a2,width,color=COLORS[m],label=m)
 b.set_xticks(x,['Same\nC=4','Same\nC=16','Disjoint\nC=4','Disjoint\nC=16']);b.set_ylabel('Authorization latency (ms)');b.set_title('(b) Absolute instance medians');b.legend(ncol=2,frameon=False);save(fig,'fig3_ablation')
 # E2E tables
 e2er=[]
 for d in e2e:
  for r in d['timing']['rows']:e2er.append({'seed':d['seed'],'instance':d['instance'],'method':r['method'],'block':r['block'],'round':r['round'],'candidate_lookup_stub_ms':r['candidate_lookup_stub_ns']/1e6,'authorization_ms':r['authorization_ns']/1e6,'user_recovery_ms':r['user_recovery_ns']/1e6,'total_ms':r['total_ns']/1e6,'planning_ms':r['planning_ms'],'header_ms':r['header_ms'],'leaf_ms':r['leaf_ms'],'interpolation_ms':r['interpolation_ms'],'final_ms':r['final_ms']})
 write_csv('end_to_end_rounds.csv',e2er);e2ei=[]
 for d in e2e:
  rows0=[r for r in e2er if r['seed']==d['seed'] and r['instance']==d['instance']];med={m:statistics.median(r['total_ms'] for r in rows0 if r['method']==m) for m in ('PT01','Union11')};e2ei.append({'seed':d['seed'],'instance':d['instance'],'pt01_total_ms':med['PT01'],'union11_total_ms':med['Union11'],'speedup':med['PT01']/med['Union11']})
 write_csv('end_to_end_instances.csv',e2ei)
 fig,(a,b)=plt.subplots(2,1,figsize=(3.35,5.35),constrained_layout=True);x=np.array([0,1])
 for r in e2ei:a.plot(x,[r['pt01_total_ms'],r['union11_total_ms']],color='#BBBBBB',lw=.7,marker='o',ms=2.5)
 meds=[statistics.median(r[k] for r in e2ei) for k in ('pt01_total_ms','union11_total_ms')];a.plot(x,meds,color='#D55E00',lw=2,marker='D',ms=4,label='Median');a.set_xticks(x,['PT01','Union11']);a.set_ylabel('Complete call (ms)');a.set_title('(a) Nine paired controlled instances');a.legend(frameon=False)
 stages=['candidate_lookup_stub_ms','planning_ms','header_ms','leaf_ms','interpolation_ms','final_ms','user_recovery_ms'];labels=['Lookup stub','Planning','Header','Leaf','Interpolation','Final transform','User recovery'];bottom=np.zeros(2)
 for stage,label,color in zip(stages,labels,['#999999','#56B4E9','#E69F00','#0072B2','#CC79A7','#009E73','#D55E00']):
  values=[statistics.mean(r[stage] for r in e2er if r['method']==m) for m in ('PT01','Union11')];b.bar(x,values,bottom=bottom,label=label,color=color);bottom+=values
 b.set_xticks(x,['PT01','Union11']);b.set_ylabel('Mean additive stage time (ms)');b.set_title('(b) Recorded stages (lookup is a stub)');b.legend(ncol=2,frameon=False,fontsize=6,loc='upper center',bbox_to_anchor=(.5,-.16));save(fig,'fig4_end_to_end')
 # Revocation
 revrows=[]
 for d in rev:
  for r in d['events']:revrows.append({'internal_nodes':d['internal_nodes'],'seed':d['seed'],**r})
 write_csv('revocation_events.csv',revrows);fig,axes=plt.subplots(3,1,figsize=(3.35,7.0),constrained_layout=True);sizes=[25,100,250]
 for metric,label,ax in [('ta_generation_ns','Time (ms)',axes[0]),('wire_bytes_total','Wire size (KiB)',axes[1]),('authorization_check_ns','Validation workload (ms)',axes[2])]:
  for size in sizes:
   vals=[r[metric]/(1e6 if metric.endswith('_ns') else 1024) for r in revrows if r['internal_nodes']==size];jitter=np.linspace(-4,4,len(vals));ax.scatter(np.array([size]*len(vals))+jitter,vals,s=10,alpha=.55,color='#0072B2');ax.plot(size,statistics.median(vals),'D',color='#D55E00',ms=4)
  ax.set_ylabel(label);ax.grid(alpha=.18);ax.set_xticks(sizes)
 axes[0].set_title('(a) TA generation');
 # add CSP median as second line/points to panel a
 for index,size in enumerate(sizes):
  vals=[r['csp_decode_generate_apply_ns']/1e6 for r in revrows if r['internal_nodes']==size];axes[0].plot(size,statistics.median(vals),'s',color='#009E73',ms=4,label='CSP median' if index==0 else None)
 axes[0].plot([],[],'D',color='#D55E00',ms=4,label='TA median');axes[0].legend(frameon=False)
 axes[1].set_title('(b) Canonical TA-to-CSP bytes');axes[2].set_title('(c) Post-update two-user validation workload');axes[2].set_xlabel('Internal policy nodes');save(fig,'fig5_revocation')
 # Stability
 stability=[]
 for stage,ds in [('discovery',disc),('holdout',hold),('end_to_end',e2e)]:
  if stage=='end_to_end':
   for d in ds:
    for m in ('PT01','Union11'):
     vals=[r['total_ns'] for r in d['timing']['rows'] if r['method']==m];stability.append({'stage':stage,'unit':f"{d['seed']}-{d['instance']}",'method':m,'retained_rounds':len(vals),'cv':statistics.stdev(vals)/statistics.mean(vals),'supplemented':d['timing']['blocks']==2})
  else:
   for d in ds:
    for m in d['timing']['medians_ns']:
     vals=[r['per_call_ns'] for r in d['timing']['rows'] if r['method']==m];stability.append({'stage':stage,'unit':d['unit_id'],'method':m,'retained_rounds':len(vals),'cv':statistics.stdev(vals)/statistics.mean(vals),'supplemented':d['timing']['blocks']==2})
 write_csv('timing_stability.csv',stability);fig,ax=plt.subplots(figsize=(3.35,2.75));groups=['discovery','holdout','end_to_end'];vals=[[r['cv']*100 for r in stability if r['stage']==g] for g in groups];bp=ax.boxplot(vals,showfliers=True,patch_artist=True);[b.set_facecolor(c) for b,c in zip(bp['boxes'],['#0072B2','#E69F00','#009E73'])];ax.axhline(5,color='#D55E00',ls='--',lw=.9);ax.set_xticks(range(1,4),['Discovery','Holdout','Controlled\nend-to-end']);ax.set_ylabel('CV of all retained rounds (%)');ax.set_title('Timing stability (no observations removed)');save(fig,'fig6_timing_stability')
 # integrity and manifest
 allraw=sorted(p for stage in ('discovery','holdout','revocation','end_to_end','smoke') for p in (EVAL/'results/raw'/stage).glob('*.json'));manifest=[{'path':str(p.relative_to(EVAL)).replace('\\','/'),'bytes':p.stat().st_size,'sha256':hashlib.sha256(p.read_bytes()).hexdigest()} for p in allraw];(OUT/'RAW_MANIFEST.json').write_text(json.dumps(manifest,indent=2)+'\n',encoding='utf-8')
 frozen=json.loads((EVAL/'protocol/frozen_sha256.json').read_text());mismatch=[n for n,h in frozen['files'].items() if hashlib.sha256((EVAL/n).read_bytes()).hexdigest()!=h]
 unique_ok=len({d['unit_id'] for d in disc})==120 and len({d['unit_id'] for d in hold})==30
 auth_rounds_ok=all(len(d['timing']['rows'])==len(d['timing']['medians_ns'])*d['timing']['rounds_per_block']*d['timing']['blocks'] for d in disc+hold)
 positive_ok=all(r['per_call_ns']>0 and r['elapsed_ns']>0 and r['batch_calls']>0 for r in rounds) and all(r['total_ns']>0 for d in e2e for r in d['timing']['rows']) and all(min(r['ta_generation_ns'],r['csp_decode_generate_apply_ns'],r['wire_bytes_total'])>0 for r in revrows)
 config_counts={(layout,count):sum(d['configuration']['layout']==layout and d['configuration']['candidate_count']==count for d in disc) for layout in ('Same-Branch','Disjoint-Branches') for count in (4,16)}
 audit={'schema':'v2-final-integrity-audit','passed':not mismatch and len(disc)==120 and len(hold)==30 and len(rev)==9 and len(e2e)==9 and unique_ok and auth_rounds_ok and positive_ok and set(config_counts.values())=={30},'frozen_hash_mismatches':mismatch,'counts':{'discovery_units':len(disc),'holdout_units':len(hold),'revocation_sequences':len(rev),'revocation_events':len(revrows),'end_to_end_units':len(e2e),'authorization_rounds':len(rounds),'end_to_end_rounds':len(e2er),'raw_files_including_smoke':len(allraw)},'configuration_counts':{f'{k[0]}_C{k[1]}':v for k,v in config_counts.items()},'checks':{'unique_unit_ids':unique_ok,'round_count_matches_blocks':auth_rounds_ok,'all_recorded_values_positive':positive_ok},'correctness':{'authorization_units':all(d['correctness']['independent_complete_set_and_keys'] for d in disc+hold),'revocation':all(d['correctness'] for d in rev),'end_to_end':all(d['correctness'] for d in e2e)}};(OUT/'INTEGRITY_AUDIT.json').write_text(json.dumps(audit,indent=2)+'\n',encoding='utf-8')
 print(json.dumps({'audit':audit,'speedups':summary,'e2e_median_speedup':statistics.median(r['speedup'] for r in e2ei),'figures':6},indent=2))
if __name__=='__main__':main()

from __future__ import annotations
import ctypes,json,random,statistics,sys,time
from pathlib import Path
HERE=Path(__file__).resolve();EVAL=HERE.parents[1];ROOT=EVAL.parents[1];sys.path.insert(0,str(ROOT))
from new_attribute_only_evaluation.v2_20260916_01.scripts.run_benchmark import atomic,build,cv
from new_attribute_only_evaluation.v2_20260916_01.src.execution import execute,recover_all
def pin():
 k=ctypes.windll.kernel32;k.GetCurrentProcess.restype=ctypes.c_void_p;k.SetProcessAffinityMask(k.GetCurrentProcess(),ctypes.c_size_t(1))
def one(method,postings,cloud,tk,user,state,oracle):
 t0=time.perf_counter_ns();candidates=list(postings['controlled-marker']);t1=time.perf_counter_ns();result=execute(method,cloud,state,tk,candidates);t2=time.perf_counter_ns();keys=recover_all(state,user,result.outputs);t3=time.perf_counter_ns()
 if set(keys)!=set(candidates) or any(bytes(k)!=bytes(oracle.file_keys[n]) for n,k in keys.items()):raise AssertionError('end-to-end correctness')
 return {'candidate_lookup_stub_ns':t1-t0,'authorization_ns':t2-t1,'user_recovery_ns':t3-t2,'total_ns':t3-t0,**result.phases.row_ms()}
def run(seed,instance,cfg,out):
 dst=out/f'seed{seed}_instance{instance}.json'
 if dst.exists():return
 tree,ta,cloud,tk,user,state,oracle,targets=build(seed,instance,16,'Same-Branch',cfg['internal_nodes']);postings={'controlled-marker':sorted(targets)};methods=('PT01','Union11')
 for _ in range(cfg['warmups']):
  for m in methods:one(m,postings,cloud,tk,user,state,oracle)
 rows=[];blocks=1
 for block in range(2):
  for rr in range(cfg['rounds']):
   order=list(methods);random.Random(seed*1000+instance*100+block*10+rr).shuffle(order)
   for position,m in enumerate(order):rows.append({'block':block,'round':rr,'order':position,'method':m,**one(m,postings,cloud,tk,user,state,oracle)})
  if block==0:
   initial={m:cv([x['total_ns'] for x in rows if x['method']==m]) for m in methods}
   if max(initial.values())<=cfg['cv_threshold']:break
   blocks=2
 atomic(dst,{'schema':'paper-current-backend-controlled-e2e-v2','seed':seed,'instance':instance,'layout':'Same-Branch','candidate_count':16,'candidate_source':'controlled in-memory dictionary lookup stub; not encrypted EII','timing_endpoint':'recovered file keys; excludes file download and payload decryption','correctness':True,'timing':{'warmups':cfg['warmups'],'rounds_per_block':cfg['rounds'],'blocks':blocks,'initial_cv':initial,'rows':rows}})
def main():
 pin();cfg=json.loads((EVAL/'config.json').read_text());out=EVAL/'results/raw/end_to_end';units=[(s,i) for s in cfg['end_to_end_seeds'] for i in range(3)];done=sum((out/f'seed{s}_instance{i}.json').exists() for s,i in units)
 for s,i in units:
  if not (out/f'seed{s}_instance{i}.json').exists():run(s,i,cfg,out);done+=1
  atomic(EVAL/'results/end_to_end_status.json',{'completed':done,'expected':len(units),'latest':[s,i]});print(json.dumps({'stage':'end_to_end','completed':done,'expected':len(units)}),flush=True)
if __name__=='__main__':main()

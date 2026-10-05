from __future__ import annotations
import ctypes,json,sys,time
from pathlib import Path
HERE=Path(__file__).resolve();EVAL=HERE.parents[1];ROOT=EVAL.parents[1];sys.path.insert(0,str(ROOT))
from new_attribute_only_evaluation.v2_20260916_01.src.access_tree import synthetic_tree
from new_attribute_only_evaluation.v2_20260916_01.src.backend import CloudService,DataOwnerEncryptor,TrustedAuthority,advance_test_oracle,cipher_material_bytes,rematerialize_for_test
from new_attribute_only_evaluation.v2_20260916_01.src.execution import execute,recover_all
def pin():
 k=ctypes.windll.kernel32;k.GetCurrentProcess.restype=ctypes.c_void_p;k.SetProcessAffinityMask(k.GetCurrentProcess(),ctypes.c_size_t(1))
def atomic(p,v):p.parent.mkdir(parents=True,exist_ok=True);q=p.with_suffix('.tmp');q.write_text(json.dumps(v,indent=2)+'\n',encoding='utf-8');q.replace(p)
def check(cloud,state,oracle,users):
 for tk,user in users:
  out=execute('Union11',cloud,state,tk,set(state.tree.internal_ids)).outputs;keys=recover_all(state,user,out)
  if any(bytes(key)!=bytes(oracle.file_keys[node]) for node,key in keys.items()):raise AssertionError('recovered key mismatch')
 return {str(tk.uid):sorted(execute('Union11',cloud,state,tk,set(state.tree.internal_ids)).outputs) for tk,user in users}
def run(size,seed,out):
 dst=out/f'size{size}_seed{seed}.json'
 if dst.exists():return
 tree=synthetic_tree(size,seed);attrs=sorted({tree.nodes[n].attribute for n in tree.leaf_ids});ta=TrustedAuthority(attrs,16,seed);owner=DataOwnerEncryptor(ta.public,ta.user_tree,seed+1);cloud=CloudService(ta.public,ta.user_tree,seed+2);users=[ta.keygen(0,attrs),ta.keygen(1,attrs)];state,oracle=owner.encrypt(tree);tas=ta.initialize_revocation_state(state)
 events=[{attrs[0]:{0}},{attrs[min(1,len(attrs)-1)]:{0,2}},{},{attrs[0]:{1}}];rows=[]
 for index,event in enumerate(events):
  start=time.perf_counter_ns();payload,tas,tao=ta.create_update(state,tas,event);ta_ns=time.perf_counter_ns()-start
  start=time.perf_counter_ns();wire=payload.to_bytes();serialization_ns=time.perf_counter_ns()-start
  start=time.perf_counter_ns();state,cspo=cloud.apply_serialized_update(state,wire);csp_ns=time.perf_counter_ns()-start
  oracle=advance_test_oracle(oracle,tao,cspo);rebuilt=rematerialize_for_test(state,ta,oracle)
  if cipher_material_bytes(state)!=cipher_material_bytes(rebuilt):raise AssertionError('incremental/rematerialized mismatch')
  start=time.perf_counter_ns();authorized=check(cloud,state,oracle,users);authorization_ns=time.perf_counter_ns()-start
  rows.append({'event':index,'request':{a:sorted(u) for a,u in event.items()},'epoch':state.epoch,'ta_generation_ns':ta_ns,'serialization_ns':serialization_ns,'csp_decode_generate_apply_ns':csp_ns,'wire_bytes_total':len(wire),'wire_bytes_crypto':sum(len(bytes(x)) for values in payload.file_eta_factors.values() for x in values)+sum(len(bytes(x)) for values in payload.leaf_eta_factors.values() for x in values)+sum(len(bytes(x)) for headers in payload.replacement_headers.values() for x in headers.values()),'authorization_check_ns':authorization_ns,'authorized_targets':authorized,'incremental_equals_rematerialized':True})
 atomic(dst,{'schema':'paper-current-backend-revocation-v2','internal_nodes':size,'seed':seed,'events':rows,'correctness':True})
def main():
 pin();cfg=json.loads((EVAL/'config.json').read_text());out=EVAL/'results/raw/revocation';units=[(n,s) for n in (25,100,250) for s in cfg['revocation_seeds']];done=sum((out/f'size{n}_seed{s}.json').exists() for n,s in units)
 for n,s in units:
  if not (out/f'size{n}_seed{s}.json').exists():run(n,s,out);done+=1
  atomic(EVAL/'results/revocation_status.json',{'completed':done,'expected':len(units),'latest':[n,s]});print(json.dumps({'stage':'revocation','completed':done,'expected':len(units)}),flush=True)
if __name__=='__main__':main()

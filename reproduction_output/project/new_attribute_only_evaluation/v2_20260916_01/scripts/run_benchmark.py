from __future__ import annotations

import argparse, ctypes, hashlib, json, math, random, statistics, sys, time
from pathlib import Path

HERE=Path(__file__).resolve(); EVAL=HERE.parents[1]; ROOT=EVAL.parents[1]; sys.path.insert(0,str(ROOT))
from new_attribute_only_evaluation.v2_20260916_01.src.access_tree import synthetic_tree
from new_attribute_only_evaluation.v2_20260916_01.src.backend import CloudService,DataOwnerEncryptor,TrustedAuthority
from new_attribute_only_evaluation.v2_20260916_01.src.execution import execute,recover_all
from new_attribute_only_evaluation.v2_20260916_01.src.workload import choose_targets

FORMAL_METHODS=("PT00","PT01","Union10","Union11")

def pin_cpu_zero():
    kernel=ctypes.windll.kernel32;kernel.GetCurrentProcess.restype=ctypes.c_void_p;kernel.SetProcessAffinityMask.argtypes=(ctypes.c_void_p,ctypes.c_size_t);kernel.SetProcessAffinityMask.restype=ctypes.c_int
    if not kernel.SetProcessAffinityMask(kernel.GetCurrentProcess(),ctypes.c_size_t(1)):raise OSError("CPU affinity failed")
def atomic(path,value):
    path.parent.mkdir(parents=True,exist_ok=True);tmp=path.with_suffix(path.suffix+".tmp");tmp.write_text(json.dumps(value,indent=2)+"\n",encoding="utf-8");tmp.replace(path)
def unit_id(stage,seed,instance,count,layout):return hashlib.sha256(repr(("paper-v2",stage,seed,instance,count,layout)).encode()).hexdigest()
def cv(values):return statistics.stdev(values)/statistics.mean(values) if len(values)>1 else 0.0
def build(seed,instance,count,layout,internal_nodes=100):
    s=seed*100+instance;tree=synthetic_tree(internal_nodes,s);attrs={tree.nodes[x].attribute for x in tree.leaf_ids};ta=TrustedAuthority(attrs,16,s);owner=DataOwnerEncryptor(ta.public,ta.user_tree,s+1);cloud=CloudService(ta.public,ta.user_tree,s+2);tk,user=ta.keygen(0,attrs);state,oracle=owner.encrypt(tree);rng=random.Random(s*1000+count*10+(layout=="Disjoint-Branches"));targets=choose_targets(tree,count,layout,rng);return tree,ta,cloud,tk,user,state,oracle,targets
def verify(methods,cloud,tk,user,state,oracle,targets):
    operations={}
    for method in methods:
        result=execute(method,cloud,state,tk,targets,collect_metrics=True);recovered={n:bytes(k) for n,k in recover_all(state,user,result.outputs).items()}
        expected={n:bytes(oracle.file_keys[n]) for n in targets}
        if recovered!=expected:raise AssertionError(f"complete set/key mismatch: {method}")
        operations[method]={"counts":result.counts.row(),"metrics":result.metrics,"phases_ms":result.phases.row_ms()}
    return operations
def timed(method,cloud,tk,state,targets,calls):
    started=time.perf_counter_ns();output=None
    for _ in range(calls):output=execute(method,cloud,state,tk,targets).outputs
    return time.perf_counter_ns()-started,output
def run_unit(stage,seed,instance,count,layout,methods,output_dir,config):
    identifier=unit_id(stage,seed,instance,count,layout);destination=output_dir/f"{identifier}.json"
    if destination.exists():return False
    tree,ta,cloud,tk,user,state,oracle,targets=build(seed,instance,count,layout,config["internal_nodes"]);operations=verify(methods,cloud,tk,user,state,oracle,targets)
    smoke=stage=="smoke";warmups=2 if smoke else config["warmups"];rounds=5 if smoke else config["rounds"];minimum_ns=int((10 if smoke else config["minimum_batch_ms"])*1e6);calls={}
    for method in methods:
        elapsed,_=timed(method,cloud,tk,state,targets,1);calls[method]=max(1,math.ceil(minimum_ns*1.2/elapsed))
    rows=[];blocks=1;initial_cv={}
    for block in range(2):
        total=rounds+(warmups if block==0 else 0)
        for rr in range(total):
            measured=block==1 or rr>=warmups;round_id=rr if block else rr-warmups;order=list(methods);random.Random(int(identifier[:16],16)+block*100+rr).shuffle(order)
            for position,method in enumerate(order):
                elapsed,_=timed(method,cloud,tk,state,targets,calls[method])
                while measured and elapsed<minimum_ns:
                    calls[method]=max(calls[method]+1,math.ceil(calls[method]*minimum_ns*1.1/elapsed));elapsed,_=timed(method,cloud,tk,state,targets,calls[method])
                if measured:rows.append({"block":block,"round":round_id,"order":position,"method":method,"batch_calls":calls[method],"elapsed_ns":elapsed,"per_call_ns":elapsed/calls[method]})
        if block==0:
            initial_cv={m:cv([r["per_call_ns"] for r in rows if r["method"]==m]) for m in methods}
            if smoke or max(initial_cv.values())<=config["cv_threshold"]:break
            blocks=2
    medians={m:statistics.median(r["per_call_ns"] for r in rows if r["method"]==m) for m in methods}
    atomic(destination,{"schema":"paper-current-backend-benchmark-v2","stage":stage,"unit_id":identifier,"configuration":{"internal_nodes":config["internal_nodes"],"seed":seed,"instance":instance,"candidate_count":count,"layout":layout},"state":{"tree_id":state.tree_id,"policy_hash":state.policy_hash,"ciphertext_id":state.ciphertext_id,"epoch":state.epoch,"ciphertext_version":state.ciphertext_version,"tk_id":tk.tk_id},"candidate_ids":sorted(targets),"correctness":{"independent_complete_set_and_keys":True},"operations":operations,"timing":{"warmups":warmups,"rounds_per_block":rounds,"blocks":blocks,"initial_cv":initial_cv,"medians_ns":medians,"rows":rows}});return True
def main():
    parser=argparse.ArgumentParser();parser.add_argument("--stage",choices=["smoke","discovery","holdout"],required=True);args=parser.parse_args();config=json.loads((EVAL/"config.json").read_text(encoding="utf-8"));pin_cpu_zero()
    if args.stage=="smoke":units=[(config["smoke_seeds"][0],0,16,"Same-Branch"),(config["smoke_seeds"][1],0,16,"Disjoint-Branches")];methods=FORMAL_METHODS
    elif args.stage=="discovery":units=[(s,i,c,l) for l in config["layouts"] for c in config["candidate_counts"] for s in config["discovery_seeds"] for i in range(5)];methods=FORMAL_METHODS
    else:units=[(s,i,16,"Same-Branch") for s in config["holdout_seeds"] for i in range(5)];methods=("PT01","Union11")
    output=EVAL/"results/raw"/args.stage;completed=sum((output/unit_id(args.stage,*unit)).exists() for unit in units)
    for unit in units:
        if run_unit(args.stage,*unit,methods,output,config):completed+=1
        atomic(EVAL/f"results/{args.stage}_status.json",{"completed":completed,"expected":len(units),"latest":unit});print(json.dumps({"stage":args.stage,"completed":completed,"expected":len(units)}),flush=True)
if __name__=="__main__":main()

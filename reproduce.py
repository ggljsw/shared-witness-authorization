"""Read-only validation plus correctness/reanalysis in an isolated copy."""
from pathlib import Path
import hashlib,json,shutil,subprocess,sys,os

BASE=Path(__file__).resolve().parent
PROJECT=BASE/'project'
EVAL=PROJECT/'new_attribute_only_evaluation/v2_20260916_01'
def digest(p):return hashlib.sha256(p.read_bytes()).hexdigest()

def main():
    frozen=json.loads((EVAL/'protocol/frozen_sha256.json').read_text(encoding='utf-8'))['files']
    for name,expected in frozen.items():
        if digest(EVAL/name)!=expected:raise RuntimeError('Frozen hash mismatch: '+name)
    raw=json.loads((EVAL/'results/analysis/RAW_MANIFEST.json').read_text(encoding='utf-8'))
    for item in raw:
        p=EVAL/item['path']
        if p.stat().st_size!=item['bytes'] or digest(p)!=item['sha256']:
            raise RuntimeError('Raw mismatch: '+item['path'])
    out=BASE/'reproduction_output'
    if out.exists():
        n=2
        while (BASE/f'reproduction_output_{n}').exists():n+=1
        out=BASE/f'reproduction_output_{n}'
    work=out/'project'
    shutil.copytree(PROJECT,work)
    e=work/'new_attribute_only_evaluation/v2_20260916_01'
    paper=out/'paper';shutil.copytree(BASE/'paper',paper)
    env=os.environ.copy();env['MPLCONFIGDIR']=str(out/'.mplconfig');env['PYTHONDONTWRITEBYTECODE']='1'
    checks=[]
    steps=[
        ('correctness',[sys.executable,'-m','unittest','discover','-s',str(e/'tests'),'-v']),
        ('statistics',[sys.executable,str(e/'scripts/analyze_and_plot.py')]),
        ('paper_figures',[sys.executable,str(paper/'scripts/replot_v2.py'),str(e)]),
        ('pt00_ablation',[sys.executable,str(paper/'scripts/plot_ablation.py')]),
    ]
    for name,command in steps:
        result=subprocess.run(command,cwd=work,env=env,text=True,capture_output=True)
        log=out/(name+'.log');log.write_text(result.stdout+result.stderr,encoding='utf-8')
        checks.append({'check':name,'return_code':result.returncode,'log':str(log.relative_to(BASE))})
        (out/'REPRODUCTION_CHECK.json').write_text(json.dumps(checks,indent=2),encoding='utf-8')
        if result.returncode:raise RuntimeError(name+' failed; see '+str(log))
    audit=json.loads((e/'results/analysis/INTEGRITY_AUDIT.json').read_text(encoding='utf-8'))
    if not audit['passed']:raise RuntimeError('Regenerated integrity audit failed')
    for name,expected in frozen.items():
        if digest(EVAL/name)!=expected:raise RuntimeError('Original evidence changed: '+name)
    print('PASS: frozen hashes, raw, independent tests, statistics and paper plots.')
    print('Formal timing was not started. Output: '+str(out))

if __name__=='__main__':main()

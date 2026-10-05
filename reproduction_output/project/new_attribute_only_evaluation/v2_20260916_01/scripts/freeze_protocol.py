from __future__ import annotations
import hashlib,json,platform,sys,time
from datetime import datetime,timezone
from pathlib import Path
HERE=Path(__file__).resolve();EVAL=HERE.parents[1]
INCLUDE=["config.json","PROTOCOL_V2.md","FORMULA_CODE_MAP.md","ROLE_ISOLATION_REPORT.md","ENVIRONMENT.md","CORRECTNESS_GATE.md"]
INCLUDE += [str(p.relative_to(EVAL)).replace('\\','/') for d in ('src','tests','scripts') for p in sorted((EVAL/d).glob('*.py'))]
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def main():
 files={name:sha(EVAL/name) for name in sorted(set(INCLUDE))};record={'schema':'paper-current-backend-freeze-v2','created_utc':datetime.now(timezone.utc).isoformat(),'formal_results_present_at_freeze':any(any((EVAL/'results/raw'/d).glob('*.json')) for d in ('discovery','holdout','revocation','end_to_end')),'protocol_sha256':files['PROTOCOL_V2.md'],'files':files}
 if record['formal_results_present_at_freeze']:raise SystemExit('refusing to freeze after formal results exist')
 (EVAL/'protocol').mkdir(exist_ok=True);(EVAL/'protocol/frozen_sha256.json').write_text(json.dumps(record,indent=2)+'\n',encoding='utf-8');print(json.dumps({'files':len(files),'protocol_sha256':record['protocol_sha256']}))
if __name__=='__main__':main()

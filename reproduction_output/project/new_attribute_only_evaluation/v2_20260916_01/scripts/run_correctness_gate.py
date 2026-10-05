from __future__ import annotations

import hashlib
import json
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

HERE = Path(__file__).resolve(); EVAL = HERE.parents[1]; ROOT = EVAL.parents[1]

SCENARIOS = [
    ("complete-all", "All authorized targets and file keys equal the independent recursive threshold oracle", "test_complete_authorization_set_matrix"),
    ("complete-partial", "Only recursively authorized targets are returned", "test_complete_authorization_set_matrix"),
    ("complete-deny", "No target is returned when no policy is satisfied", "test_complete_authorization_set_matrix"),
    ("empty-candidates", "Empty candidates produce an empty set", "test_complete_authorization_set_matrix"),
    ("mixed-candidates", "Authorized and unauthorized candidates are separated", "test_complete_authorization_set_matrix"),
    ("nested-threshold", "Nested threshold decisions match an independent recursion", "test_complete_authorization_set_matrix"),
    ("repeated-attribute", "Repeated labels preserve distinct leaf identities", "test_complete_authorization_set_matrix"),
    ("layouts", "Two independently generated layouts match the oracle", "test_complete_authorization_set_matrix"),
    ("revocation-no-alternative", "A revoked attribute denies access when no alternative path exists", "test_revocation_reject_alternative_and_control_user"),
    ("revocation-alternative", "A legal alternative path continues to authorize", "test_revocation_reject_alternative_and_control_user"),
    ("revocation-control-user", "A non-revoked control user retains access", "test_revocation_reject_alternative_and_control_user"),
    ("cumulative-revocation", "Successive attributes and users accumulate", "test_cumulative_revocation_and_independent_rematerialization"),
    ("duplicate-revocation", "Duplicate membership is idempotent while the epoch drift remains valid", "test_cumulative_revocation_and_independent_rematerialization"),
    ("incremental-rematerialized", "Every incremental state equals an independent concrete rematerialization", "test_cumulative_revocation_and_independent_rematerialization"),
    ("cache-context", "Injected old entries miss across queries, users, keys, ciphertexts and epochs", "test_cache_scope_actual_stale_entry_injection"),
    ("serialization", "Canonical round trip preserves groups; malformed inputs are rejected", "test_update_serialization_roundtrip_and_rejection"),
    ("cloud-wire-boundary", "Cloud update consumes decoded wire material plus CSP state only", "test_update_serialization_roundtrip_and_rejection"),
    ("role-isolation", "Owner, cloud transform, user recovery, TA and CSP interfaces keep their assigned secrets", "test_role_and_secret_isolation_interfaces"),
]


def sha(path): return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    output = EVAL / "correctness"; output.mkdir(parents=True, exist_ok=True)
    command = [sys.executable, "-m", "unittest", "discover", "-s", str(EVAL / "tests"), "-v"]
    completed = subprocess.run(command, cwd=ROOT, text=True, capture_output=True)
    log = completed.stdout + completed.stderr; (output / "unittest.log").write_text(log, encoding="utf-8")
    passed = completed.returncode == 0
    records = [{"id": key, "expected": expected, "actual": "verified by named test; see unittest.log" if passed else "test suite failed", "passed": passed, "evidence": ["correctness/unittest.log", f"tests/test_correctness_gate.py::{test}"]} for key,expected,test in SCENARIOS]
    sources = [EVAL/"src/backend.py",EVAL/"src/execution.py",EVAL/"src/planner.py",EVAL/"tests/test_correctness_gate.py",EVAL/"tests/test_v2_roles.py"]
    report = {"schema":"v2-correctness-gate-1","created_utc":datetime.now(timezone.utc).isoformat(),"passed":passed,"test_return_code":completed.returncode,"properties":records,"source_sha256":{str(p.relative_to(EVAL)).replace("\\","/"):sha(p) for p in sources}}
    (output/"CORRECTNESS_GATE.json").write_text(json.dumps(report,indent=2)+"\n",encoding="utf-8")
    rows = "\n".join(f"| `{r['id']}` | {r['expected']} | {r['actual']} | {'PASS' if r['passed'] else 'FAIL'} |" for r in records)
    md = f"""# V2 correctness gate

**Overall status: {'PASS' if passed else 'FAIL'}**

This gate checks implementation behavior and role boundaries. It is not a cryptographic security proof. Expected target sets come from an independent recursive threshold oracle that does not call the witness planner. Each returned target is additionally checked against the independently retained file key.

| Scenario | Expected property | Actual result | Status |
|---|---|---|---|
{rows}

## Evidence and boundary

- Executed command: `{' '.join(command)}`
- Full output: `correctness/unittest.log`
- Machine-readable results: `correctness/CORRECTNESS_GATE.json`
- Incremental revocation state is compared byte-for-byte with a separately rematerialized state after every event.
- The TA-to-CSP object is encoded canonically and decoded with group constructors before the cloud accepts it.
- Duplicate revocation means that adding an already revoked `(attribute,user)` pair does not rotate that attribute mask again. The protocol epoch and synchronized polynomial drift still advance.
- Cache isolation is tested by injecting entries captured from a prior real execution; no check relies only on calling a cache-clear function.
"""
    (EVAL/"CORRECTNESS_GATE.md").write_text(md,encoding="utf-8")
    print(json.dumps({"passed":passed,"properties":len(records),"log":str(output/"unittest.log")}))
    raise SystemExit(completed.returncode)


if __name__ == "__main__": main()

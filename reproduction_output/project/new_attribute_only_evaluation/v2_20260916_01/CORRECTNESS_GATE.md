# V2 correctness gate

**Overall status: PASS**

This gate checks implementation behavior and role boundaries. It is not a cryptographic security proof. Expected target sets come from an independent recursive threshold oracle that does not call the witness planner. Each returned target is additionally checked against the independently retained file key.

| Scenario | Expected property | Actual result | Status |
|---|---|---|---|
| `complete-all` | All authorized targets and file keys equal the independent recursive threshold oracle | verified by named test; see unittest.log | PASS |
| `complete-partial` | Only recursively authorized targets are returned | verified by named test; see unittest.log | PASS |
| `complete-deny` | No target is returned when no policy is satisfied | verified by named test; see unittest.log | PASS |
| `empty-candidates` | Empty candidates produce an empty set | verified by named test; see unittest.log | PASS |
| `mixed-candidates` | Authorized and unauthorized candidates are separated | verified by named test; see unittest.log | PASS |
| `nested-threshold` | Nested threshold decisions match an independent recursion | verified by named test; see unittest.log | PASS |
| `repeated-attribute` | Repeated labels preserve distinct leaf identities | verified by named test; see unittest.log | PASS |
| `layouts` | Two independently generated layouts match the oracle | verified by named test; see unittest.log | PASS |
| `revocation-no-alternative` | A revoked attribute denies access when no alternative path exists | verified by named test; see unittest.log | PASS |
| `revocation-alternative` | A legal alternative path continues to authorize | verified by named test; see unittest.log | PASS |
| `revocation-control-user` | A non-revoked control user retains access | verified by named test; see unittest.log | PASS |
| `cumulative-revocation` | Successive attributes and users accumulate | verified by named test; see unittest.log | PASS |
| `duplicate-revocation` | Duplicate membership is idempotent while the epoch drift remains valid | verified by named test; see unittest.log | PASS |
| `incremental-rematerialized` | Every incremental state equals an independent concrete rematerialization | verified by named test; see unittest.log | PASS |
| `cache-context` | Injected old entries miss across queries, users, keys, ciphertexts and epochs | verified by named test; see unittest.log | PASS |
| `serialization` | Canonical round trip preserves groups; malformed inputs are rejected | verified by named test; see unittest.log | PASS |
| `cloud-wire-boundary` | Cloud update consumes decoded wire material plus CSP state only | verified by named test; see unittest.log | PASS |
| `role-isolation` | Owner, cloud transform, user recovery, TA and CSP interfaces keep their assigned secrets | verified by named test; see unittest.log | PASS |

## Evidence and boundary

- Executed command: `D:\分层属性基\文章实验\kss\.venv\Scripts\python.exe -m unittest discover -s D:\分层属性基\文章实验\kss\new_attribute_only_evaluation\v2_20260916_01\tests -v`
- Full output: `correctness/unittest.log`
- Machine-readable results: `correctness/CORRECTNESS_GATE.json`
- Incremental revocation state is compared byte-for-byte with a separately rematerialized state after every event.
- The TA-to-CSP object is encoded canonically and decoded with group constructors before the cloud accepts it.
- Duplicate revocation means that adding an already revoked `(attribute,user)` pair does not rotate that attribute mask again. The protocol epoch and synchronized polynomial drift still advance.
- Cache isolation is tested by injecting entries captured from a prior real execution; no check relies only on calling a cache-clear function.

# V1 audit findings and v2 repairs

This supplement preserves the frozen `FORMULA_CODE_MAP.md` and summarizes the implementation transition without changing any frozen file.

| V1 audited difference | V2 repair | Evidence |
|---|---|---|
| Public interface exposed `g1^alpha` and omitted paper fields | Publishes `Z^alpha`, `g1^theta`, `B_i`, `f1`, `f2`; master exponents are separate | `FORMULA_CODE_MAP.md`; role test |
| Cloud transformation object serialized `tau` | Separate cloud key and user-private state; cloud interface never accepts the latter | role-isolation test |
| Owner Encrypt depended on scheme/master state and independent attribute masks | Public-only owner API implements `r_d/H2/rho` and common initial rho | encryption and runtime interface tests |
| TA generated both eta and delta; scalar oracle data shared with update application | TA wire contains group factors; CSP independently samples delta after strict decode | serialization, role and rematerialization tests |
| Update size was a partial estimate | Actual canonical byte-stream length plus separate crypto-element subtotal | `data/revocation_events.csv` |
| PT01 built an unused union witness | Union construction is inside Union10/Union11 branches only | frozen `src/execution.py:114–138` |
| Cache lacked an explicit ciphertext instance/query boundary | Key binds query ID and ciphertext ID in addition to prior context | injected-old-cache test |

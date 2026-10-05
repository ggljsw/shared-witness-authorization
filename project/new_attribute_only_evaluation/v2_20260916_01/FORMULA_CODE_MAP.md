# Current-paper formula and v2 code map

Paper source: `09162013/extracted_v1/paper/main.tex` (Setup/KeyGen lines 155–174, Encrypt 176–196, update 198–218, Transform/Recover 220–234). Code line numbers below refer to the frozen-candidate v2 source. This map distinguishes formula agreement, functional tests, and interface isolation; it is not a security proof.

| Stage | Paper equation / rule | V2 source | Groups and input → output | Holder / interface | Result |
|---|---|---|---|---|---|
| Setup | `Z=e(g1,g2)`; publish `f1=g2^β1`, `f2=g2^β2`, `Z^α`, `g1^θ`, `B_i=g1^(v_root/t_i)` | `src/backend.py:28–41, 274–282` | G2, GT, G1, G1 | TA creates `PublicParameters`; master exponents remain in `TAMasterSecret` | Aligned |
| KeyGen | `D1=g1^[τ(α+r)/β1]`, `D2=g1^[τr/β2]`, `K_i=(g1^r H(i)^ri)^τ`, `L_i=g2^(τri)`, `E_i,j=g2^(τt_i ri/v_j)` | `src/backend.py:284–295` | D1,D2,K∈G1; L,E∈G2 | TA returns cloud TK and separate `UserPrivateState` | Aligned; tested |
| H and H2 | Domain-separated hash-to-G1; `H2:G1→F_p*` | `src/algebra.py:45–49`; `src/backend.py:21–24` | bytes→G1; canonical G1 bytes→nonzero scalar | Public algorithms | Aligned; nonzero enforced |
| Encrypt initialization | choose `r_d`; `A=g1^r_d`; `ρ=H2((g1^θ)^r_d)`; initial `k_i,0=ρ`; header `B_i^ρ` | `src/backend.py:323–338` | public parameters + owner randomness → ciphertext | `DataOwnerEncryptor` receives no TA master secret | Aligned; tested without TA state |
| File ciphertext | `C1=ck·(Z^α)^(s+z)`, `C2=g2^(s+z)`, `C3=f1^(s+z)`, `C4=f2^z` | `src/backend.py:329–334` | GT, G2, G2, G2 | Data owner | Aligned; C2 retained |
| Leaf/header | `A_y=g2^s_y`, `B_y=H(i)^s_y g1^k`; `F_i,j,b=g1^(k v_j/t_i)` | `src/backend.py:333–335`; update headers `315–317` | A∈G2; B,F∈G1 | Owner initially; TA replaces changed headers | Aligned |
| Attribute-header unsealing | reusable `e(F,E)` only under identical context | `src/execution.py:82–98`; `src/planner.py:68–70` | G1×G2→GT | Cloud, query-local cache | Aligned; key also binds query and ciphertext instance |
| Leaf transform | `T_y=e(K,A)e(F,E)/e(B,L)` | `src/execution.py:82–98` | GT | Cloud | Aligned; tested with repeated labels |
| Internal interpolation | Lagrange reconstruction over the selected threshold children | `src/execution.py:99–108` | GT children→GT parent | Cloud | Aligned; independent recursive oracle checks target set |
| Final transform | `R_x=e(D1,C3)/(T_x e(D2,C4))` | `src/execution.py:109–112` | GT | Cloud | Aligned; C2 unused as specified |
| Recover | `ck=C1/R_x^(1/τ)` | `src/backend.py:368`; `src/execution.py:140–142` | GT + user-private τ→GT | User only | Aligned; cloud interface has no user state |
| Attribute update | TA produces η-consistent factors and changed mask/header; CSP samples δ and applies update | TA `src/backend.py:300–320`; CSP `341–363` | canonical TA wire bytes + CSP state→next ciphertext epoch | Split TA/CSP | Aligned in implemented lifecycle; incremental state equals independent rematerialization |
| Serialization | Binding metadata, all group elements, cover and header replacement encoded canonically | `src/backend.py:123–239` | bytes with strict decode and group constructors | TA→CSP | Implemented; actual total bytes recorded separately from crypto-element bytes |
| Cache invalidation | Bind entries to query, ciphertext, tree/policy, user/TK, attribute/cover, epoch and version | `src/planner.py:68–70` | context tuple→GT | Cloud query scope | Tested using injected stale entries |

## Supported lifecycle

The v2 experiments cover a fixed user tree, initially empty revocation sets, cumulative attribute/user revocation, and idempotent duplicate revocation membership. A duplicate-only request advances the global synchronized polynomial epoch but does not rotate an unchanged attribute mask. New-tree initialization, attribute regrant, user-tree growth, rollback protection, collusion resistance and formal security are outside this implementation experiment.

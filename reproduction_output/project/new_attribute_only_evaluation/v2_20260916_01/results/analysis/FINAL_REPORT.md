# V2 final experimental report

## Decision

The v2 correctness gate and final integrity audit pass. The implementation now matches the current paper formulas and intended software role interfaces for the tested lifecycle. The results support a bounded systems claim: when 16 candidate targets lie in the same hierarchy branch, merging their authorization witnesses reduces repeated leaf and interpolation work relative to a per-target method with the same attribute-header cache. The effect is reproduced by a fresh-seed holdout.

The discovery estimate is 1.163x [1.154, 1.171] and the independent holdout estimate is 1.159x [1.147, 1.183]. Benefits are small for C=4 and for Disjoint-Branches. The controlled complete call shows 1.091x median speedup, with high timing variability and a candidate lookup stub rather than encrypted EII search.

## Correctness and isolation

The 18-property gate covers complete authorization sets from an independent recursive oracle, recovered file keys, nested thresholds, repeated attributes, negative and alternative revocation paths, a control user, cumulative and duplicate revocations, bytewise incremental/rematerialized state equality, real stale-cache injection, canonical serialization, malformed wire data, and explicit role interfaces. The cloud transformation key excludes tau; owner Encrypt does not receive the TA master secret; the cloud update interface receives only ciphertext state and decoded TA wire bytes and samples delta itself.

These are functional and implementation-boundary checks. They are not an IND-CPA, collusion-resistance, rollback-security or other cryptographic proof.

## Revocation measurements

Nine cumulative sequences contain 36 events. Median TA generation / CSP decode-generation-application times are approximately 143.9/142.9 ms at 25 internal nodes, 571.9/575.5 ms at 100, and 1450.1/1425.1 ms at 250. Median canonical wire sizes are 23.3, 92.1 and 229.8 KiB. Wire size is measured from the actual serialized stream; a separate CSV column reports only serialized group-element bytes.

The recorded post-update value is a two-user, all-internal-target validation workload, not a single authorization query. It is labeled accordingly in Fig. 5 and must not be cited as per-query authorization latency. Three tested sizes are insufficient for an asymptotic-complexity claim.

## Limitations

- Candidate layouts and policies are synthetic; natural hierarchies may exhibit different witness overlap.
- The controlled candidate lookup is a Python dictionary operation and provides no evidence about encrypted EII latency.
- The tested lifecycle excludes user-tree growth, regrant, new-tree initialization and rollback protection.
- Correctness and role separation do not constitute a formal security proof.
- End-to-end variability is high, and all high-CV observations are retained.
- FullTree11 is covered by the correctness gate but was not timed in the clean 120-unit ablation, as fixed by the protocol.
- A Windows affinity helper in the frozen revocation/end-to-end scripts lacked an explicit handle type and exited before producing raw. Both stages were launched with an external wrapper that first set the same CPU-0 affinity correctly, then called the unchanged frozen `main()`. The frozen files and hashes remained unchanged.

## Evidence

The raw boundaries are 120 discovery units, 30 holdout units, 9 revocation sequences/36 events and 9 controlled end-to-end units. There are 5,936 retained authorization round rows and 238 retained controlled end-to-end round rows. `INTEGRITY_AUDIT.json` passes with no frozen-file hash mismatch.

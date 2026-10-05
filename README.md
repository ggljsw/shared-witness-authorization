# Public research artifact: shared-witness authorization v2

The authoritative frozen backend is under `project/new_attribute_only_evaluation/v2_20260916_01/`.
It is independent of v1, the former 480-unit experiment, and the former 1.241x result.

## Reproduce existing evidence

Historical environment: CPython 3.14.6, Windows 11, dependencies in requirements.txt. New hardware can reanalyze fixed data but cannot reproduce identical timing values.
Install dependencies in a fresh environment, then run from this package directory:

```
python reproduce.py
```

This checks frozen hashes and raw manifests, runs independent correctness tests, and regenerates statistics and the six publication figures in `reproduction_output/`. It never launches formal timing and does not overwrite bundled evidence.
The paper figures use the revised PT00-normalized ablation, while the original analysis script is preserved with its original figure layout and normalization. Both derive statistics from the same retained raw.

Directories: `project/` frozen code and evidence; `paper/` revised manuscript/figures/plot scripts; `VERSION_AUDIT.*` version and hash checks; `CHECKS/` packaging verification; `SHA256SUMS.json` complete package manifest.

Timing runners are archived for inspection. Do not run them against bundled raw: future timing belongs in a new experiment version. Their Windows affinity issue and historical workaround remain documented in the original final report. The safe reproduction wrapper does not run those paths.

This is a research artifact with seeded pseudo-randomness and test-oracle utilities, not production cryptographic software or a security proof. No deployment keys or credentials are supplied.
No new license is asserted by this packaging step. The authors should select their distribution license and check third-party/data rights before hosting the package. Public hosting has not been performed.

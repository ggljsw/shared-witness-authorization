# Independent statistics recheck

All values below were recomputed from retained raw rounds by `scripts/analyze_and_plot.py`. V1 observations, the old 480-unit run and the old 1.241x result are absent. An instance latency is the median of its 7 or 14 retained rounds. The primary ratio is formed inside each instance as `median(PT01) / median(Union11)` and configuration estimates are medians of those 30 instance ratios. The 95% interval is the frozen 10,000-replicate percentile bootstrap over six whole five-instance seed clusters with RNG seed 20260917.

| Dataset | Layout | C | Instances / seeds | Median speedup | 95% seed-cluster CI |
|---|---|---:|---:|---:|---:|
| Discovery | Same-Branch | 4 | 30 / 6 | 1.011x | [1.004, 1.069] |
| Discovery | Same-Branch | 16 | 30 / 6 | 1.163x | [1.154, 1.171] |
| Discovery | Disjoint-Branches | 4 | 30 / 6 | 1.005x | [1.001, 1.009] |
| Discovery | Disjoint-Branches | 16 | 30 / 6 | 1.019x | [1.015, 1.034] |
| Independent holdout | Same-Branch | 16 | 30 / 6 | 1.159x | [1.147, 1.183] |

The Same-Branch C=16 discovery result corresponds to a 14.0% authorization-time reduction, and the independent holdout corresponds to 13.7%. The holdout used seeds that did not occur in v1, v2 development, or v2 smoke.

The controlled complete-call result over nine instances is 1.091x by the same instance-ratio median rule. Median complete-call latency is 168.97 ms for PT01 and 152.70 ms for Union11, an 8.4% reduction. The candidate stage is an in-memory dictionary lookup stub, so this is not an EII search-performance result.

## Ablation interpretation

For Same-Branch C=16, the median within-instance ratios relative to Union11 are PT00 1.218x, PT01 1.163x, Union10 1.026x and Union11 1.000x. PT00/Union11 combines header caching and witness sharing and is not used as the isolated shared-witness effect. PT01/Union11 is the main comparison because both use the same query-level header cache.

The scatter plots use instance records. Witness overlap is `1 - union_unique_nodes / unmerged_witness_nodes`. Operation reduction uses the same instance and is `1 - Union11_count / PT01_count`. These associations support the proposed mechanism but do not establish causality.

## Stability

No high-CV observations were removed. Discovery contains 480 instance-method combinations, 148 above 5% after all retained rounds; 74/120 units triggered a supplemental block. Holdout contains 60 combinations, 5 above 5%; 6/30 units were supplemented. Controlled end-to-end contains 18 combinations, 15 above 5%; 8/9 units were supplemented. The end-to-end timing is consequently much noisier and should be interpreted with that limitation.

## Differences from v1

V1 reference numbers are not expected to match because v2 changes the public interface, keeps tau user-private, implements public-only owner encryption and paper rho/H2 initialization, separates TA/CSP update roles, fixes PT01's unused union construction, and uses fresh formal seeds. No v1 and v2 observation is pooled.

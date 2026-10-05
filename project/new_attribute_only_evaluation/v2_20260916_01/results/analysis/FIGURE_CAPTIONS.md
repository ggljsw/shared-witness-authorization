# Figure captions

## Fig. 1 — Primary authorization speedup

**English.** PT01-to-Union11 paired authorization speedup. Points are medians of 30 within-instance ratios; error bars are 95% percentile intervals from 10,000 seed-cluster bootstrap replicates over six five-instance seed clusters. The first four rows are the discovery ablation and the separated final row is the fresh-seed holdout. Both methods use the same query-level attribute-header cache and include their own required planning. The dotted lines mark 1.0x and 1.2x; the holdout interval is not claimed to exceed 1.2x.

**中文说明。** 主比较隔离了跨目标见证共享，因为 PT01 与 Union11 具有相同属性头缓存。明显收益只出现在同分支大候选集，并由独立保持集复现。

## Fig. 2 — Overlap and operation reuse

**English.** Instance-level association between PT01/Union11 speedup and (a) witness overlap, `1 - |union unique nodes| / sum |per-target witness nodes|`, and (b) executed leaf-transform reduction, `1 - Union11 leaves / PT01 leaves`. Colors and markers identify candidate layout and size. The horizontal line marks no speedup. These associations do not by themselves establish causality; repeated attribute labels remain distinct leaves, while only identical header terms may be cached.

**中文说明。** 散点全部来自实例级记录，没有用汇总中位数伪造观测。图只说明结构重叠、实际运算减少和加速方向一致。

## Fig. 3 — Cache/sharing ablation

**English.** Authorization ablation over 120 discovery instances. PT00/PT01 execute per-target witnesses without cross-target node reuse; PT01 enables the query header cache. Union10/Union11 merge witness nodes; Union11 enables the same cache. Panel (a) normalizes each paired instance to Union11; panel (b) shows medians of absolute instance latency by workload. PT00/Union11 combines two optimizations and is not the main shared-witness effect.

**中文说明。** 主比较仍是 PT01/Union11。完整四开关消融表明同分支 C=16 的收益主要来自见证节点共享，属性头缓存是另一独立因素。

## Fig. 4 — Controlled complete call

**English.** Nine paired Same-Branch, C=16 controlled complete-call instances, ending at recovered file keys. Panel (a) connects the same instance and highlights medians. Panel (b) stacks means of recorded additive stages from the retained rounds; stage medians are not summed. Candidate acquisition is an in-memory dictionary lookup stub, not encrypted EII search. File download and payload decryption are excluded.

**中文说明。** 完整调用中位加速为 1.091x，但波动较高。搜索段只是受控候选输入接口，不能写成真实 EII 性能。

## Fig. 5 — Attribute-revocation update costs

**English.** Costs from nine cumulative revocation sequences and 36 events across 25, 100 and 250 internal policy nodes. Small points are event observations and diamonds/squares are medians. Panel (a) separates TA eta/material generation from CSP decode/delta/application; panel (b) is the actual canonical TA-to-CSP byte-stream length; panel (c) is the recorded post-update two-user, all-target validation workload, not a single-query authorization latency. The three scales do not establish asymptotic complexity.

**中文说明。** 通信量来自真实规范序列化字节流。更新后耗时是完整正确性验证工作负载，已避免误标为单次授权。

## Fig. 6 — Timing stability

**English.** Coefficient-of-variation distributions computed from all retained rounds for each instance-method combination. The dashed line marks the frozen 5% trigger. Triggered units retain both the initial and one supplemental block; no high-CV result is removed. Revocation events are excluded because they are stateful single observations rather than repeated rounds.

**中文说明。** 发现集与端到端仍有较多高波动组合，图中全部保留并披露。

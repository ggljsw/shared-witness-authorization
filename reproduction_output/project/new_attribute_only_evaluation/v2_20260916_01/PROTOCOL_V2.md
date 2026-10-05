# Frozen v2 evaluation protocol

Frozen after the independent correctness gate and two operational smoke units, before formal v2 timing. The freeze is local and is not a third-party preregistration. V1, the archived backend, the old 480-unit experiment and the old 1.241x result are excluded.

## Methods and comparison

- PT00: deterministic per-target minimum witnesses; no query header cache.
- PT01: deterministic per-target minimum witnesses; query-wide attribute-header cache. It does not construct a union witness.
- Union10: merged witness nodes; no query header cache.
- Union11: merged witness nodes plus the same query-wide attribute-header cache condition used by PT01.
- FullTree11 is used by the correctness gate and is not timed in the 120-unit ablation.

The primary ratio is each instance's `median(PT01 rounds) / median(Union11 rounds)`. PT00/Union11 combines header caching and witness sharing and is not the primary effect.

## Workloads

- Discovery/ablation: 100 internal nodes; Same-Branch and Disjoint-Branches; candidate counts 4 and 16; six fixed seeds and five instances per seed, totaling 120 paired units. All four ablation methods are timed.
- Holdout: 30 Same-Branch, candidate-count-16 units from six fixed seeds not used by v1 or by v2 development/smoke, five instances per seed. Only PT01 and Union11 are timed.
- Revocation: 25, 100 and 250 internal nodes, three fixed seeds, nine cumulative four-event sequences (36 events). TA generation, canonical serialization, CSP decode/delta/application, actual total wire bytes, crypto-element bytes, and post-update authorization are recorded separately.
- Controlled end-to-end: three fixed seeds and three instances per seed, nine Same-Branch candidate-count-16 instances. Candidate acquisition is a controlled in-memory dictionary lookup stub, not a real encrypted EII implementation. Endpoint is recovered file keys and excludes file download and payload decryption.

All listed formal seeds are in `config.json`. Smoke seeds 97001 and 98003 are excluded from formal statistics.

## Timing and statistics

Formal authorization timing pins one process to logical CPU 0, uses three warmups and seven recorded rounds, and calibrates each batch to at least 20 ms. Method order is deterministically shuffled per round. If any method's first-block CV exceeds 5%, all methods in that instance receive exactly one further seven-round block; all 14 values remain in analysis. No other result-dependent extension is allowed.

Per-method instance latency is the median of all retained per-call rounds. Ratios are formed inside each instance. Configuration estimates are medians of instance ratios. The 95% percentile interval resamples whole five-instance seed clusters 10,000 times with RNG seed 20260917. Discovery and holdout remain separate; batch calls and rounds are not independent samples.

Each method includes its own required planning and authorization work. User recovery is outside the authorization benchmark and separately measured in the controlled end-to-end experiment. Stage medians are not summed to create total medians.

## Stop and reporting rules

Any complete-target mismatch, file-key mismatch, incremental/rematerialized state mismatch, malformed-transfer acceptance, frozen hash mismatch or raw-integrity failure stops subsequent performance phases. Results are retained and reported regardless of direction or effect size. No speedup threshold is an acceptance condition, and no formal parameter is selected from partial results.

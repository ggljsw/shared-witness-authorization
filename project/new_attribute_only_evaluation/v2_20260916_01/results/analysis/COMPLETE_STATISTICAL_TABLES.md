# Complete v2 statistical tables

All latency values are milliseconds. Configuration speedups are medians of within-instance ratios. Confidence intervals use the frozen 10,000-replicate seed-cluster percentile bootstrap.

## Primary comparison

| Set | Layout | C | Instances | Seeds | PT01/Union11 | 95% CI |
|---|---|---:|---:|---:|---:|---:|
| Discovery | Same-Branch | 4 | 30 | 6 | 1.0107 | [1.0043, 1.0685] |
| Discovery | Same-Branch | 16 | 30 | 6 | 1.1633 | [1.1540, 1.1708] |
| Discovery | Disjoint-Branches | 4 | 30 | 6 | 1.0054 | [1.0008, 1.0087] |
| Discovery | Disjoint-Branches | 16 | 30 | 6 | 1.0193 | [1.0148, 1.0340] |
| Holdout | Same-Branch | 16 | 30 | 6 | 1.1586 | [1.1468, 1.1827] |

## Absolute authorization latency medians

| Set/layout | C | PT00 | PT01 | Union10 | Union11 |
|---|---:|---:|---:|---:|---:|
| Discovery Same | 4 | 44.616 | 44.786 | 43.884 | 43.628 |
| Discovery Same | 16 | 170.858 | 161.625 | 142.065 | 138.571 |
| Discovery Disjoint | 4 | 40.831 | 40.858 | 40.893 | 40.727 |
| Discovery Disjoint | 16 | 165.613 | 160.399 | 161.630 | 157.152 |
| Holdout Same | 16 | — | 160.690 | — | 136.515 |

## Median paired ratios relative to Union11

| Discovery workload | PT00 | PT01 | Union10 | Union11 |
|---|---:|---:|---:|---:|
| Same, C=4 | 1.0190 | 1.0107 | 0.9984 | 1.0000 |
| Same, C=16 | 1.2177 | 1.1633 | 1.0255 | 1.0000 |
| Disjoint, C=4 | 1.0074 | 1.0054 | 1.0016 | 1.0000 |
| Disjoint, C=16 | 1.0583 | 1.0193 | 1.0285 | 1.0000 |

## Mechanism metrics: instance medians

| Discovery workload | Witness overlap | Leaf reduction | Interpolation reduction | Pairing reduction |
|---|---:|---:|---:|---:|
| Same, C=4 | 0.0000 | 0.0000 | 0.0000 | 0.0000 |
| Same, C=16 | 0.2558 | 0.2632 | 0.2601 | 0.1304 |
| Disjoint, C=4 | 0.0000 | 0.0000 | 0.0000 | 0.0000 |
| Disjoint, C=16 | 0.0421 | 0.0465 | 0.0385 | 0.0219 |

## Controlled complete call

| Statistic | PT01 | Union11 |
|---|---:|---:|
| Median instance total | 168.969 | 152.697 |
| Mean candidate lookup stub | 0.002 | 0.001 |
| Mean planning | 0.653 | 0.716 |
| Mean header work | 13.890 | 14.067 |
| Mean leaf transforms | 76.149 | 56.138 |
| Mean interpolation | 8.253 | 6.931 |
| Mean final transforms | 60.152 | 63.121 |
| Mean user recovery | 28.019 | 29.380 |

The median within-instance complete-call ratio is 1.0912. Stage rows are means of additive measurements; they are not summed medians.

## Revocation events

Each size has 12 events from three four-event sequences.

| Internal nodes | TA generation | CSP decode/delta/apply | Serialization | Total wire bytes | Crypto bytes | Two-user validation workload |
|---:|---:|---:|---:|---:|---:|---:|
| 25 | 143.919 | 142.912 | 0.757 | 23,828.5 | 22,968 | 836.175 |
| 100 | 571.907 | 575.473 | 2.918 | 94,329 | 91,368 | 3,304.375 |
| 250 | 1,450.144 | 1,425.138 | 6.931 | 235,329 | 228,168 | 7,992.815 |

Wire columns are bytes. The validation workload is not a single authorization request.

## Timing stability

| Stage | Instance-method combinations | Final CV >5% | Units receiving supplemental block |
|---|---:|---:|---:|
| Discovery | 480 | 148 | 74/120 |
| Holdout | 60 | 5 | 6/30 |
| Controlled complete call | 18 | 15 | 8/9 |

No high-CV observation was removed. Revocation events are stateful single measurements and are not included in the CV table.

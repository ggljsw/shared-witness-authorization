# V2 experimental environment

Captured on 2026-09-16 before formal timing.

| Item | Value | Evidence |
|---|---|---|
| CPU | Intel Core i7-10750H @ 2.60 GHz; 12 logical CPUs | Windows processor registry; earlier environment capture confirms 12 logical CPUs |
| Physical memory | 15.84 GiB | Windows `GlobalMemoryStatusEx` |
| OS | Windows 11, build reported by Python as 10.0.26200 | `platform.platform()` |
| Python | CPython 3.14.6, MSC v.1944, 64 bit | `sys.version` in `.venv` |
| BLS12-381 backend | `chia_rs` 0.49.0 | `importlib.metadata` |
| Hash-to-curve support | `py-ecc` 8.0.0 | `importlib.metadata` |
| Plotting | Matplotlib 3.11.2; NumPy 2.5.3 | `importlib.metadata` |
| Timer | `time.perf_counter_ns`, Windows QueryPerformanceCounter, reported resolution 100 ns | Python clock info and runner source |
| Threads / affinity | one benchmark process pinned to logical CPU 0 | benchmark, revocation and end-to-end runners |
| GC | CPython default; not disabled | runner source |
| Authorization warmup / rounds | 3 warmups; 7 recorded rounds per block | frozen config/protocol |
| Batch rule | calibrated to at least 20 ms net batch duration, normalized per call | benchmark runner |
| Supplemental rule | if any method has initial CV >5%, add exactly one complete 7-round block for all methods and retain all observations | frozen protocol |

Smoke uses 2 warmups, 5 rounds and 10 ms batches only for operational validation. It is excluded from formal statistics. Historical v1 environment descriptions are not reused as evidence for v2; v2 formal measurements run on the environment above.

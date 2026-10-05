# Current-paper attribute-only evaluation v2

This directory is an independent backend and evidence package. It does not overwrite or pool v1, the archived backend, the old 480-unit run, or the old 1.241x result.

## Key artifacts

- `FORMULA_CODE_MAP.md`: current-paper equations, groups, roles and source locations.
- `CORRECTNESS_GATE.md` and `correctness/CORRECTNESS_GATE.json`: 18-property gate and machine-readable evidence.
- `ROLE_ISOLATION_REPORT.md`: public/TA/owner/cloud/user interface boundaries.
- `PROTOCOL_V2.md`, `config.json`, `protocol/frozen_sha256.json`: frozen formal protocol and hashes.
- `results/raw/`: smoke, discovery, holdout, revocation and controlled end-to-end records.
- `results/analysis/`: independent CSVs, six figures, captions, integrity audit and final report.

## Reproduction

From the project root with the supplied `.venv`:

```powershell
.\.venv\Scripts\python.exe new_attribute_only_evaluation/v2_20260916_01/scripts/run_correctness_gate.py
$env:MPLCONFIGDIR='D:\分层属性基\文章实验\kss\.mplconfig'
.\.venv\Scripts\python.exe new_attribute_only_evaluation/v2_20260916_01/scripts/analyze_and_plot.py
```

The analysis command uses the fixed raw records and regenerates all CSV, PDF and PNG files. Formal timing commands and the CPU-affinity wrapper are documented in `PROTOCOL_V2.md` and `results/analysis/FINAL_REPORT.md`. Re-running timing creates a new performance observation and should use a new versioned result directory rather than replacing this evidence.

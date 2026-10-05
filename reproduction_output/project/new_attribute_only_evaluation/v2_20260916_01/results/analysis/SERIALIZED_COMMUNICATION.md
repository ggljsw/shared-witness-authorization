# TA-to-CSP serialized communication

`TAUpdatePayload.to_bytes()` is the measured transfer representation. It includes a magic/version tag, tree identifier, 32-byte policy hash, ciphertext version, source and destination epochs, node identifiers, length framing, all eta update factors, changed-attribute identifiers, cover-node identifiers and replacement headers. `from_bytes()` requires an exact canonical round trip and rejects invalid magic, lengths, UTF-8, duplicates, cover/header disagreement, malformed G1/G2/GT encodings, truncation and trailing bytes.

`wire_bytes_total` in `data/revocation_events.csv` is `len(payload.to_bytes())` and is the actual encoded transfer length. `wire_bytes_crypto` is the sum of encoded group elements only; it deliberately excludes binding and protocol metadata. Test-oracle scalars, file keys, TA master secrets, revoked-set oracle copies, eta scalars and CSP delta scalars are not in the byte stream.

Across the 12 events per policy size, median total lengths are 23,828.5 B (25 nodes), 94,329 B (100 nodes) and 235,329 B (250 nodes). A half-byte median is possible because it is the midpoint of two integer event sizes; each individual message length is an integer.

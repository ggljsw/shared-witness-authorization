# Correctness and role-isolation report

The v2 implementation passes the 18-property correctness gate in `correctness/CORRECTNESS_GATE.json`. Functional correctness, paper-formula consistency and software interface isolation are supported by executable checks. These checks do not establish cryptographic security.

- Public parameters expose `f1`, `f2`, `Z^alpha`, `g1^theta` and `B_i`; `TAMasterSecret` is a separate object.
- `CloudTransformationKey` contains no `tau`; `UserPrivateState` alone supplies `tau` to Recover.
- `DataOwnerEncryptor` accepts public parameters and owner inputs. A runtime test removes access to the TA master object before Encrypt and still obtains a valid ciphertext.
- Cloud transformation receives the cloud key, ciphertext and candidates. It does not receive `UserPrivateState`.
- The TA creates eta factors and a canonical byte stream. `CloudService.apply_serialized_update` decodes that stream, samples delta from its own RNG and applies the update. Its public update interface receives only `(state, wire)`.
- Test-oracle shares, masks, file keys and scalar drift exist in private test structures. They are absent from the transmitted object and cloud API.
- Wire decoding enforces magic/version structure, exact lengths, UTF-8, canonical encoding, unique identifiers, complete tree coverage, cover/header equality and concrete G1/G2/GT decoding. Truncation, corruption and trailing data are rejected.
- The measured `wire_bytes_total` is the actual length of the canonical stream, including binding and protocol metadata. `wire_bytes_crypto` is reported separately as the sum of serialized group elements.
- PT01 constructs and executes only per-target witnesses. Union construction occurs only for Union10/Union11 or outside timing when diagnostic metrics are explicitly requested.

Evidence: `tests/test_correctness_gate.py`, `tests/test_v2_roles.py`, `correctness/unittest.log`, and `CORRECTNESS_GATE.md`.

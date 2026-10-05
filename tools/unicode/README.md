# Frozen Unicode tables for `H_w_v1`

`gen_ucd17.py` generates `crates/pvault-core/src/ucd17/tables.rs`, the
Unicode 17.0.0 data behind the generated-word passphrase handling `H_w_v1`
(spec 7.3, `docs/M3_READINESS.md` D2): assigned code points (`Cn` refusal),
NFKC (decompositions, combining classes, compositions with exclusions), full
default case folding (`CaseFolding.txt` statuses C and F) and `White_Space`.
The tables are frozen: `H_w_v1` output must never change for an existing
vault, so they are not updated with dependencies. A future Unicode version
would be a new, separately reviewed `H_w_v2`.

The script never runs pvault code. It checks the archive and every input file
against pinned SHA-256 values, writes the tables, copies
`NormalizationTest.txt` to `crates/pvault-core/testdata/unicode/`, and records
inputs and output hashes in `MANIFEST.txt`.

```sh
curl -sSfLO https://www.unicode.org/Public/17.0.0/ucd/UCD.zip
python3 tools/unicode/gen_ucd17.py --ucd-zip UCD.zip --out-root .
git diff --exit-code   # the checked-in files must be reproduced exactly
```

CI runs the same regeneration (`unicode-tables` job). The Rust tests check the
tables against `NormalizationTest.txt` and against `unicode-normalization` for
every code point. Licensing: Unicode License V3, `third_party/unicode/LICENSE`
and `THIRD_PARTY_NOTICES.md`.

#!/usr/bin/env python3
"""Generates pvault's frozen Unicode 17.0.0 tables for H_w_v1 (spec 7.3, D2).

This script never runs pvault code. It reads the official Unicode Character
Database archive, checks every input against a pinned SHA-256, and writes:

- crates/pvault-core/src/ucd17/tables.rs  (Rust tables, generated)
- tools/unicode/MANIFEST.txt               (inputs, hashes, outputs)

Usage (development only):

    python3 tools/unicode/gen_ucd17.py --ucd-zip PATH/UCD.zip --out-root .

The UCD archive comes from https://www.unicode.org/Public/17.0.0/ucd/UCD.zip.
The generated tables are derived from Unicode data files and are covered by
the Unicode License V3 (third_party/unicode/LICENSE).
"""

import argparse
import hashlib
import io
import sys
import zipfile
from pathlib import Path

GENERATOR_VERSION = "1"
UCD_URL = "https://www.unicode.org/Public/17.0.0/ucd/UCD.zip"
PINNED = {
    "UCD.zip": "2066d1909b2ea93916ce092da1c0ee4808ea3ef8407c94b4f14f5b7eb263d28e",
    "UnicodeData.txt": "2e1efc1dcb59c575eedf5ccae60f95229f706ee6d031835247d843c11d96470c",
    "DerivedNormalizationProps.txt": "71fd6a206a2c0cdd41feb6b7f656aa31091db45e9cedc926985d718397f9e488",
    "CompositionExclusions.txt": "2f239196ef3b5b61db5cc476e9bd80f534d15aa1b74e1be1dea5d042a344c85f",
    "CaseFolding.txt": "ff8d8fefbf123574205085d6714c36149eb946d717a0c585c27f0f4ef58c4183",
    "PropList.txt": "130dcddcaadaf071008bdfce1e7743e04fdfbc910886f017d9f9ac931d8c64dd",
    "NormalizationTest.txt": "5019ffd530751a741900c849c0e010332f142a3612234639bd200b82138a87db",
}

S_BASE, L_BASE, V_BASE, T_BASE = 0xAC00, 0x1100, 0x1161, 0x11A7
L_COUNT, V_COUNT, T_COUNT = 19, 21, 28
N_COUNT = V_COUNT * T_COUNT
S_COUNT = L_COUNT * N_COUNT


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def check(name, data):
    actual = sha256(data)
    if actual != PINNED[name]:
        sys.exit(f"{name}: SHA-256 {actual} does not match pinned {PINNED[name]}")


def data_lines(text):
    for line in text.splitlines():
        line = line.split("#", 1)[0].strip()
        if line:
            yield line


def parse_range(field):
    if ".." in field:
        a, b = field.split("..")
        return int(a, 16), int(b, 16)
    v = int(field, 16)
    return v, v


def parse_unicode_data(text):
    assigned, ccc, decomp = [], {}, {}
    first = None
    for line in text.splitlines():
        f = line.split(";")
        cp, name, gc = int(f[0], 16), f[1], f[2]
        assert gc != "Cn"
        if name.endswith(", First>"):
            first = cp
            continue
        if name.endswith(", Last>"):
            assigned.append((first, cp))
            first = None
            continue
        assigned.append((cp, cp))
        if int(f[3]):
            ccc[cp] = int(f[3])
        if f[5]:
            parts = f[5].split()
            compat = parts[0].startswith("<")
            if compat:
                parts = parts[1:]
            decomp[cp] = (compat, [int(p, 16) for p in parts])
    return merge(assigned), ccc, decomp


def merge(ranges):
    ranges.sort()
    out = []
    for a, b in ranges:
        if out and a <= out[-1][1] + 1:
            out[-1] = (out[-1][0], max(out[-1][1], b))
        else:
            out.append((a, b))
    return out


def hangul_decompose(cp):
    s = cp - S_BASE
    l, v, t = L_BASE + s // N_COUNT, V_BASE + (s % N_COUNT) // T_COUNT, T_BASE + s % T_COUNT
    return [l, v] if t == T_BASE else [l, v, t]


def full_compat(cp, decomp):
    if S_BASE <= cp < S_BASE + S_COUNT:
        return hangul_decompose(cp)
    if cp not in decomp:
        return [cp]
    out = []
    for d in decomp[cp][1]:
        out.extend(full_compat(d, decomp))
    return out


def parse_full_composition_exclusion(text):
    excluded = set()
    for line in data_lines(text):
        rng, prop = [x.strip() for x in line.split(";")[:2]]
        if prop == "Full_Composition_Exclusion":
            a, b = parse_range(rng)
            excluded.update(range(a, b + 1))
    return excluded


def parse_case_folding(text):
    fold = {}
    for line in data_lines(text):
        code, status, mapping = [x.strip() for x in line.split(";")[:3]]
        if status in ("C", "F"):
            cp = int(code, 16)
            assert cp not in fold, hex(cp)
            fold[cp] = [int(m, 16) for m in mapping.split()]
    return fold


def parse_white_space(text):
    ranges = []
    for line in data_lines(text):
        rng, prop = [x.strip() for x in line.split(";")[:2]]
        if prop == "White_Space":
            ranges.append(parse_range(rng))
    return merge(ranges)


def rust_ranges(name, ranges):
    body = "".join(f"    (0x{a:04X}, 0x{b:04X}),\n" for a, b in ranges)
    return f"pub(super) static {name}: &[(u32, u32)] = &[\n{body}];\n"


def rust_index(name, table):
    """`table` maps code point to a list of code points."""
    index, data = [], []
    for cp in sorted(table):
        index.append((cp, len(data), len(table[cp])))
        data.extend(table[cp])
    assert len(data) < 65536 and max(n for _, _, n in index) < 256
    idx = "".join(f"    (0x{cp:04X}, {off}, {n}),\n" for cp, off, n in index)
    dat = "".join(f"    0x{d:04X},\n" for d in data)
    return (
        f"pub(super) static {name}_INDEX: &[(u32, u16, u8)] = &[\n{idx}];\n\n"
        f"pub(super) static {name}_DATA: &[u32] = &[\n{dat}];\n"
    )


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--ucd-zip", required=True, type=Path)
    parser.add_argument("--out-root", required=True, type=Path)
    args = parser.parse_args()

    raw_zip = args.ucd_zip.read_bytes()
    check("UCD.zip", raw_zip)
    files = {}
    with zipfile.ZipFile(io.BytesIO(raw_zip)) as z:
        for name in PINNED:
            if name == "UCD.zip":
                continue
            data = z.read(name)
            check(name, data)
            files[name] = data.decode("utf-8")

    assigned, ccc, decomp = parse_unicode_data(files["UnicodeData.txt"])
    excluded = parse_full_composition_exclusion(files["DerivedNormalizationProps.txt"])
    fold = parse_case_folding(files["CaseFolding.txt"])
    white = parse_white_space(files["PropList.txt"])

    # Full compatibility decomposition (recursive), for code points that
    # decompose. Hangul syllables are handled algorithmically at run time.
    full = {}
    for cp in decomp:
        expanded = full_compat(cp, decomp)
        if expanded != [cp]:
            full[cp] = expanded

    # Primary composites: canonical two-character decompositions that are
    # not excluded from composition. Hangul is algorithmic at run time.
    compose = []
    for cp, (compat, parts) in sorted(decomp.items()):
        if not compat and len(parts) == 2 and cp not in excluded:
            compose.append((parts[0], parts[1], cp))
    compose.sort()
    assert len({(a, b) for a, b, _ in compose}) == len(compose)

    out = [
        "// @generated by tools/unicode/gen_ucd17.py. Do not edit by hand.\n",
        "// Derived from the Unicode Character Database 17.0.0 (Unicode License V3,\n",
        "// third_party/unicode/LICENSE). Inputs and SHA-256 values: tools/unicode/MANIFEST.txt.\n\n",
        "pub(super) const UNICODE_VERSION: (u8, u8, u8) = (17, 0, 0);\n\n",
        "/// Assigned code points (General_Category is not Cn), as inclusive ranges.\n",
        rust_ranges("ASSIGNED", assigned),
        "\n/// Non-zero canonical combining classes.\n",
        "pub(super) static CCC: &[(u32, u8)] = &[\n",
        "".join(f"    (0x{cp:04X}, {c}),\n" for cp, c in sorted(ccc.items())),
        "];\n\n/// Full compatibility decompositions (Hangul excluded).\n",
        rust_index("DECOMP", full),
        "\n/// Primary composites: (first, second, composite), sorted.\n",
        "pub(super) static COMPOSE: &[(u32, u32, u32)] = &[\n",
        "".join(f"    (0x{a:04X}, 0x{b:04X}, 0x{c:04X}),\n" for a, b, c in compose),
        "];\n\n/// Full default case folding (CaseFolding.txt statuses C and F).\n",
        rust_index("FOLD", fold),
        "\n/// White_Space (PropList.txt), as inclusive ranges.\n",
        rust_ranges("WHITE_SPACE", white),
    ]
    tables = "".join(out)
    target = args.out_root / "crates/pvault-core/src/ucd17/tables.rs"
    target.write_text(tables)

    manifest = [
        "pvault frozen Unicode tables (H_w_v1), generated by tools/unicode/gen_ucd17.py",
        f"generator version: {GENERATOR_VERSION}",
        f"source: {UCD_URL}",
        "license: Unicode License V3 (third_party/unicode/LICENSE)",
        "",
        "input SHA-256:",
    ]
    manifest += [f"  {name:<32} {digest}" for name, digest in PINNED.items()]
    manifest += [
        "",
        "output SHA-256:",
        f"  {'crates/pvault-core/src/ucd17/tables.rs':<40} {sha256(tables.encode())}",
        "",
        f"counts: assigned ranges {len(assigned)}, ccc {len(ccc)}, decompositions {len(full)},",
        f"        compositions {len(compose)}, case foldings {len(fold)}, white-space ranges {len(white)}",
    ]
    (args.out_root / "tools/unicode/MANIFEST.txt").write_text("\n".join(manifest) + "\n")

    nt = args.out_root / "crates/pvault-core/testdata/unicode/NormalizationTest-17.0.0.txt"
    nt.parent.mkdir(parents=True, exist_ok=True)
    nt.write_text(files["NormalizationTest.txt"])


if __name__ == "__main__":
    main()

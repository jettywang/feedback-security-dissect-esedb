"""Controlled experiments: raw bytes vs normalized sort key vs exact hits.

Run directly to print a human-readable report::

    .venv/bin/python -m experiments.run_key_equivalence

The same scenarios are asserted by the pytest suite in
``tests/test_experiments_collation.py`` so regressions are caught in CI.

Every scenario records three layers separately, never conflating them:

1. ``raw``  - the exact bytes stored in the record's text column.
2. ``key``  - the normalized index key produced by the production encoder.
3. ``hits`` - which stored records an exact cursor lookup returns.

Python ``str ==`` is shown only as a contrast; it is never used as the
matching rule. All accented/combining literals are built with explicit
``\\uXXXX`` escapes so editor/transport normalization cannot change them.
"""

from __future__ import annotations

from dissect.esedb.lcmapstring import MapFlags

from experiments.sim_esedb import (
    DEFAULT_LCMAP_FLAGS,
    SimulatedIndex,
    ascii_bytes,
    ascii_column,
    long_column,
    unicode_column,
    utf16,
)

E_ACUTE = chr(0x00E9)                  # precomposed é
E_COMBINING = chr(0x0065) + chr(0x0301)  # e + combining acute (U+0301)


def _hr(title: str) -> None:
    print()
    print("=" * 78)
    print(title)
    print("=" * 78)


def _row(label: str, text: str, raw: bytes, key: bytes) -> None:
    print(f"  {label:22s} str={text!r}")
    print(f"  {'':22s} raw_utf16={raw.hex()}")
    print(f"  {'':22s} key       ={key.hex()}  (len={len(key)})")


def experiment_unicode_single_column() -> dict:
    """Case / combining marks / accents / width on one Unicode text index."""
    _hr("Experiment 1 - single Unicode text column (LCMap 0x30401)")
    index = SimulatedIndex([unicode_column("Name")])

    nfc = f"caf{E_ACUTE}"
    nfd = f"caf{E_COMBINING}"
    upper = f"CAF{E_ACUTE}"
    fullwidth = "ＣＡＦＥ"
    plain = "cafe"
    trailing_nul = f"caf{E_ACUTE}\x00"

    rows = [
        ("NFC stored", nfc),
        ("NFD stored", nfd),
        ("uppercase stored", upper),
        ("full-width stored", fullwidth),
        ("unaccented stored", plain),
        ("trailing NUL stored", trailing_nul),
    ]
    stored = []
    for rid, (label, value) in enumerate(rows, start=1):
        raw = utf16(value)
        rec = index.insert(rid, {"Name": value}, {"Name": raw})
        entry = {"id": rid, "label": label, "value": value, "raw": raw, "key": rec.key}
        stored.append(entry)
        _row(label, value, raw, rec.key)

    print("\n  -- exact queries (database equivalence: normalized key bytes) --")
    queries = [
        ("lowercase query", nfc),
        ("uppercase query", upper),
        ("NFD query", nfd),
        ("full-width query", fullwidth),
        ("unaccented query", plain),
    ]
    results = []
    for label, query in queries:
        qraw = utf16(query)
        qkey = index.make_key({"Name": query})
        hits = index.exact_search({"Name": query})
        hit_ids = [r.record_id for r in hits]
        py_eq = [entry["id"] for entry in stored if entry["value"] == query]
        results.append({
            "label": label, "query": query, "raw": qraw, "key": qkey,
            "hit_ids": hit_ids, "python_str_equal_ids": py_eq,
        })
        print(f"  {label:22s} qstr={query!r} key={qkey.hex()}")
        print(f"  {'':22s} DB exact hits={hit_ids}  Python str== hits={py_eq}")

    return {"stored": stored, "queries": results}


def experiment_accent_distinction() -> dict:
    """Accents must remain distinct because NORM_IGNORENONSPACE is not set."""
    _hr("Experiment 2 - accents are NOT ignored by the default flags")
    index = SimulatedIndex([unicode_column("Name")])
    e = index.insert(1, {"Name": "e"}, {"Name": utf16("e")})
    ea = index.insert(2, {"Name": E_ACUTE}, {"Name": utf16(E_ACUTE)})
    print("  e  key =", e.key.hex())
    print(f"  {E_ACUTE} key =", ea.key.hex())
    print("  keys equal?", e.key == ea.key, "(expected False: diacritic 0x02 vs 0x0e)")

    accent_insensitive = SimulatedIndex(
        [unicode_column("Name")],
        lcmap_flags=DEFAULT_LCMAP_FLAGS | MapFlags.NORM_IGNORENONSPACE,
    )
    k1 = accent_insensitive.make_key({"Name": "e"})
    k2 = accent_insensitive.make_key({"Name": E_ACUTE})
    print("  with NORM_IGNORENONSPACE: e =", k1.hex(), f" {E_ACUTE} =", k2.hex(),
          " equal?", k1 == k2, "(expected True)")
    return {"default_equal": e.key == ea.key, "ignore_nonspace_equal": k1 == k2}


def experiment_ascii_branch() -> dict:
    """ASCII/Western columns use value.upper().encode(), not LCMapString."""
    _hr("Experiment 3 - ASCII / Western (cp1252) column uses simple upper()")
    index = SimulatedIndex([ascii_column("Name")])
    lower = "resume"
    upper = "RESUME"
    r1 = index.insert(1, {"Name": lower}, {"Name": ascii_bytes(lower)})
    r2 = index.insert(2, {"Name": upper}, {"Name": ascii_bytes(upper)})
    print("  lower raw =", ascii_bytes(lower).hex(), "key =", r1.key.hex())
    print("  upper raw =", ascii_bytes(upper).hex(), "key =", r2.key.hex())
    print("  same normalized key?", r1.key == r2.key, "(expected True)")
    hits = index.exact_search({"Name": "ReSuMe"})
    hit_ids = [r.record_id for r in hits]
    print("  exact search 'ReSuMe' hits record ids:", hit_ids)
    return {"key_equal": r1.key == r2.key, "hit_ids": hit_ids}


def experiment_composite_and_truncation() -> dict:
    """Composite index, KeyMost truncation, and equal-key/different-payload."""
    _hr("Experiment 4 - composite index + KeyMost truncation + later columns")
    key_most = 20
    index = SimulatedIndex(
        [unicode_column("Name"), long_column("Num")], key_most=key_most
    )

    long_a = "abcdefghijklmnop"
    long_b = "ABCDEFGHIJKLMNOP"
    r1 = index.insert(
        1, {"Name": long_a, "Num": 7},
        {"Name": utf16(long_a)}, payload={"Status": "first"},
    )
    r2 = index.insert(
        2, {"Name": long_b, "Num": 999},
        {"Name": utf16(long_b)}, payload={"Status": "second"},
    )
    print(f"  KeyMost={key_most}; stored key lengths: {len(r1.key)}, {len(r2.key)}")
    print("  rec1 key =", r1.key.hex())
    print("  rec2 key =", r2.key.hex())
    print("  keys equal despite different Num (truncated)?", r1.key == r2.key)

    hits = index.exact_search({"Name": "AbCdEfGhIjKlMnOp", "Num": 123456})
    hit_summary = [(r.record_id, r.payload["Status"], r.values["Num"]) for r in hits]
    print("  exact search with yet another Num returns:", hit_summary)
    print("  -> both records hit even though the queried Num matches neither;")
    print("     Num was never part of the comparable key due to truncation.")

    full = SimulatedIndex([unicode_column("Name"), long_column("Num")], key_most=255)
    ka = full.make_key({"Name": "abc", "Num": 1})
    kb = full.make_key({"Name": "abc", "Num": 2})
    print("  untruncated composite keys for Num=1 vs Num=2 equal?", ka == kb,
          "(expected False)")
    return {"truncated_equal": r1.key == r2.key, "truncated_hits": hit_summary,
            "untruncated_equal": ka == kb}


def experiment_normalization_is_not_python_equality() -> dict:
    """Directly contrast DB sort-key equality with Python str equality."""
    _hr("Experiment 5 - database equivalence vs Python str == vs raw bytes")
    index = SimulatedIndex([unicode_column("Name")])
    pairs = [
        ("case", "abc", "ABC"),
        ("width", "ABC", "ＡＢＣ"),
        ("accent", "e", E_ACUTE),
        ("NFC/NFD", E_ACUTE, E_COMBINING),
        ("trailing NUL", "abc", "abc\x00"),
    ]
    table = []
    print(f"  {'pair':14s} {'raw bytes equal':>16s} {'python ==':>11s} {'DB key ==':>11s}")
    for label, a, b in pairs:
        raw_a, raw_b = utf16(a), utf16(b)
        ka, kb = index.make_key({"Name": a}), index.make_key({"Name": b})
        row = {
            "label": label, "raw_equal": raw_a == raw_b,
            "python_equal": a == b, "db_key_equal": ka == kb,
        }
        table.append(row)
        print(
            f"  {label:14s} {str(row['raw_equal']):>16s} "
            f"{str(row['python_equal']):>11s} {str(row['db_key_equal']):>11s}"
        )
    print()
    print("  NFC/NFD note: Python str == is", E_ACUTE == E_COMBINING,
          "and the dissect sort key is",
          index.make_key({"Name": E_ACUTE}) == index.make_key({"Name": E_COMBINING}),
          "- the combining mark becomes a distinct diacritic weight sequence,")
    print("  so this Wine-derived implementation does NOT fold normalization "
          "forms; Windows LCMapString may behave differently.")
    return {"table": table}


def main() -> None:
    experiment_unicode_single_column()
    experiment_accent_distinction()
    experiment_ascii_branch()
    experiment_composite_and_truncation()
    experiment_normalization_is_not_python_equality()
    print()


if __name__ == "__main__":
    main()

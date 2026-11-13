# `impacket_compat` field-level review

This folder audits the difference between `dissect.esedb` in native mode and in
`impacket_compat=True` mode, for a backend preparing to switch interfaces.

Everything here is read-only. The scripts open fixtures with `"rb"` (gzip
transparently) and never write to the database. Generated reports land next to the
scripts, not in `tests/_data`.

## Files

| File | Purpose |
| --- | --- |
| `ese_compat_audit.py` | Opens each database twice (native and compat) and compares, per column and per record, the catalog definition, raw on-disk bytes, native value and compat value. Classifies every difference and writes a JSON + Markdown report. |
| `probe_multivalue_loss.py` | Proof that a multi-value containing an empty element loses information. It rewrites an in-memory copy of `multi.edb` so `LongASCII` becomes `["", "Tiny ASCII 1Tiny ASCII 2"]`, then shows the compat blob and the failed naive migrations. |
| `report.md` / `report.json` | Generated output for the eight small fixtures in `tests/_data` (`multi`, `binary`, `text`, `default`, `index`, `basic`, `Current.mdb`, `SRUDB.dat`). The large fixtures are audited on demand; see scale table below. |

## Run

```sh
.venv/bin/python audit/ese_compat_audit.py                     # all *edb.gz fixtures
.venv/bin/python audit/ese_compat_audit.py --out audit/report  # write report.md/json
.venv/bin/python audit/probe_multivalue_loss.py                # exit 1 if loss goes undetected
```

The probe exits `0` only when the audit flags the injected empty element as
`incompatible` with `empty_element_indices == [0]`.

## Classifications

| Class | Meaning | Safe to migrate? |
| --- | --- | --- |
| `equal` | Identical value and type. | N/A |
| `null_both` | NULL in both modes. | N/A |
| `representation` | Same information, different type/encoding (e.g. `b"abc"` vs `b"616263"`). | Yes, after `unhexlify`. |
| `transformed` | Lossless textual rendering of the value (e.g. int as hex text). | Yes, after reversing. |
| `dropped` | Compat returns `None` where native returns a value. | **No.** |
| `multi_unparsed` | Multi-value collapsed to one opaque hex blob. | **No.** |
| `separated_address` | Compat returns the long-value *address*, not the value. | **No.** |
| `hex_of_raw_only` | Compat hex is the raw on-disk tag payload, not the logical value. | **No.** |
| `fabricated` | Compat hex-encodes bytes that were already hex text (double encoding). | **No.** |

## Contract changes the caller must make

1. **Binary columns** (`Binary`, `LongBinary`, and every `MSys*` binary metadata
   column) move from `bytes` to a lowercase hex `bytes` string. `unhexlify` is
   mandatory, but note that compat already applied it to the *value* only for
   non-separated long values; for `Separated` values the blob is the LV address.
2. **Text columns that are not `Separated`** stay `str`; UTF-16 columns decode
   correctly. Text columns whose values live in long-value pages (`Separated`)
   return a 1-character string containing the address byte, for example `'\x01'`.
3. **Multi-value columns** are never element-wise. Native returns a `list`; compat
   returns one hex `bytes`. A caller that used to iterate must re-read natively.
   Do not `join`, `split` or otherwise fold the blob into a single value: the byte
   offsets are internal and an empty element is indistinguishable from a merged
   one.
4. **Compressed tag values** are set to `None` in compat regardless of storage
   class (`Compressed` short-circuits before the LV/compression branch).
5. **`raw=True` is not a fallback.** For columns satisfied by a *column default*
   (tagged column absent from the record), compat hex-encodes before returning, so
   `raw=True` yields hex-of-hex. Elsewhere it matches native.
6. **Catalog-derived metadata is affected before record reads.** Compat parses
   `MSysObjects` too, so `KeyFldIDs` becomes hex text; `Index.column_ids` then
   yields bogus ids (`12336`, the ASCII of `"00"`) and `Table.search`,
   `Index.make_key` and `Cursor` lookups raise `KeyError`. Column `size`, `encoding`
   and `default` may also change.
7. **GUID, numeric, Bit and DateTime scalars are unchanged** for fixed and
   non-separated variable columns (`DateTime` remains an int64 in both modes).
8. **SLV / `JET_coltypMax` / `Nil` tag values crash in compat** (`NoneType` call)
   because the compat branch calls `parse_func`, which is `None` for those types.

## Cases that cannot be converted equivalently

- `dropped`: compressed tag value (`Compressed` flag) — native decompresses,
  compat returns `None`.
- `separated_address`: long values moved to the long-value B-tree — compat hands
  back the 4-byte address, never the content.
- `multi_unparsed`: element boundaries, per-element types and empty elements are
  not recoverable from the single hex blob. Splitting on the offset table is
  possible but is exactly the kind of "decode the hex and hope" migration this
  audit warns against; the empty-element probe shows a merged element and an empty
  element can produce the same naive output.
- `fabricated`: column defaults for tagged long columns come back as hex of the
  default bytes (binary) or as a mangled UTF-16 string of those hex characters.
- Catalog metadata: index column id lists and some column defaults/sizes are
  wrong; callers that use `Table.search`, `Index.make_key` or `Cursor` cannot
  use compat mode at all.

## Notable evidence

`tests/_data/multi.edb.gz` record `Id=2`, column `LongASCII`:

- raw: `0400100054696e79204153434949203154696e792041534349492032`
- native: `["Tiny ASCII 1", "Tiny ASCII 2"]`
- compat: `b"0400100054696e79204153434949203154696e792041534349492032"`

In-memory patch of the same payload to offsets `[4, 4]` (empty first element):

- native: `["", "Tiny ASCII 1Tiny ASCII 2"]`
- compat: `b"0400040054696e79204153434949203154696e792041534349492032"`

The compat blob differs by 2 bytes in the offset table. Nothing else distinguishes
"empty then merged" from "two values"; a naive migration cannot recover the
element. The audit report shows `multi_element_byte_lengths=[0, 24]` and
`empty_element_indices=[0]`, which is how the check finds the loss.

## Fixture coverage caveat

No fixture in `tests/_data` contains a *real* multi-value with an empty element,
and none has an `SLV`/`Max` column; those two findings come from the in-memory
probe and from synthetic payloads passed through the real parser. Everything else
(the 26 `multi_unparsed` fields, 9 `separated_address` fields, 3 `dropped` fields
and 3 `fabricated` fields) is observed on disk.

## Cross-fixture scale (all shipped fixtures)

`Windows.edb` is the one large real-world fixture and it dominates the counts:

| Fixture class | `dropped` | `multi_unparsed` | `separated_address` | `fabricated` | `representation` |
| --- | --- | --- | --- | --- | --- |
| small fixtures (`multi`, `binary`, `text`, `default`, `index`, `basic`, `Current`, `SRUDB`) | 3 | 26 | 9 | 3 | 662 |
| `Windows.edb` | 19,813 | 0 | 392 | 0 | 16,435 |
| `large.edb` | 0 | 0 | 0 | 0 | 37 |

The 19,813 dropped fields are almost all `LongValue|Compressed` long text/binary
(`FileName`, `ItemPathDisplay`, `Path`, `CaseMap`, `UserData`, …): compat returns
`None` while native returns the real path or payload. This is the case that makes
compat mode unusable as a data source for Windows Search indexing tables.

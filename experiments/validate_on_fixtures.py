"""Validate the controlled experiments against real shipped ESE databases.

The simulation in ``run_key_equivalence`` uses synthetic inputs; this script
proves the same encoder is what the library uses against real on-disk nodes:

1. For every text index in ``index.edb`` the key rebuilt from a record via
   ``Index.key_from_record`` is byte-identical to the leaf node's stored key.
2. In ``Current.mdb`` five distinct CLIENTS records share one exact
   normalized secondary-index key (different primary keys, same text).
3. ``BTree.find_node`` does not implement ``bisect_left`` for duplicates: it
   can land in the middle of a run of equal keys. ``Cursor.find_all`` masks
   this by scanning backwards/forwards over the equal-key run.

Run::

    .venv/bin/python -m experiments.validate_on_fixtures
"""

from __future__ import annotations

import gzip

from dissect.esedb.btree import find_node
from dissect.esedb.esedb import EseDB

DATA = "tests/_data"


def _open(name: str):
    return gzip.open(f"{DATA}/{name}")


def validate_rebuilt_keys_match_disk() -> list[tuple[str, int, int]]:
    """Rebuilt index keys must equal the bytes actually stored on leaf nodes."""
    report = []
    with _open("index.edb.gz") as fh:
        db = EseDB(fh)
        table = db.table("index")
        for index_name in ("IxASCII", "IxUnicode", "IxLongASCII", "IxLongUnicode"):
            index = table.index(index_name)
            total = 0
            mismatches = 0
            for record in table.records():
                total += 1
                rebuilt = index.key_from_record(record)
                node = index.cursor()._primary.search(rebuilt, exact=True)
                if node.key != rebuilt:
                    mismatches += 1
            report.append((index_name, total, mismatches))
    return report


def validate_ual_duplicate_keys() -> dict:
    """Five CLIENTS rows share one normalized key but keep distinct raw rows."""
    query = {
        "AuthenticatedUserName": "blackclover\\administrator",
        "RoleGuid": "ad495fc3-0eaa-413d-ba7d-8b13fa7ec598",
        "TenantId": "2417e4c3-5467-40c5-809b-12b59a86c102",
    }
    with _open("Current.mdb.gz") as fh:
        db = EseDB(fh)
        table = db.table("CLIENTS")
        index = table.index("Username_RoleGuid_TenantId_index")
        query_key = index.make_key(query)

        leaf_matches = [n for n in index.root.iter_leaf_nodes() if n.key == query_key]
        primary_keys = [n.data.tobytes() for n in leaf_matches]

        cursor = index.cursor()
        records = list(cursor.find_all(**query))
        raw_name = bytes(records[0].get("AuthenticatedUserName", raw=True))

        # find_node landing position inside the equal-key run (not bisect_left).
        landing = find_node(index.root, query_key).num
        equal_indices = [
            i for i in range(index.root.node_count) if index.root.node(i).key == query_key
        ]

        # Indexed columns match by collation; non-indexed filters use Python ==.
        case_changed = dict(query, AuthenticatedUserName="BLACKCLOVER\\ADMINISTRATOR")
        case_hits = len(list(index.cursor().find_all(**case_changed)))
        non_index_filtered = len(list(index.cursor().find_all(Day204=4, **query)))

    return {
        "query_key": query_key,
        "equal_leaf_count": len(leaf_matches),
        "distinct_primary_keys": sorted(set(primary_keys)),
        "find_all_count": len(records),
        "raw_name_bytes": raw_name,
        "find_node_landing": landing,
        "equal_key_indices": equal_indices,
        "landing_is_first": landing == equal_indices[0],
        "case_changed_hits": case_hits,
        "non_index_filtered_hits": non_index_filtered,
    }


def main() -> None:
    print("=" * 78)
    print("Fixture validation A - rebuilt key == on-disk leaf key (index.edb)")
    print("=" * 78)
    for name, total, mismatches in validate_rebuilt_keys_match_disk():
        status = "OK" if mismatches == 0 else "MISMATCH"
        print(f"  {name:14s} records={total} mismatches={mismatches} [{status}]")

    print()
    print("=" * 78)
    print("Fixture validation B - equal normalized key, different records (Current.mdb)")
    print("=" * 78)
    info = validate_ual_duplicate_keys()
    print("  query key (hex)        :", info["query_key"].hex())
    print("  raw stored name bytes  :", info["raw_name_bytes"].hex())
    print("  leaf nodes equal to key:", info["equal_leaf_count"])
    print("  distinct primary keys  :", [k.hex() for k in info["distinct_primary_keys"]])
    print("  Cursor.find_all hits   :", info["find_all_count"])
    print("  equal-key node indices :", info["equal_key_indices"])
    print("  find_node lands at idx :", info["find_node_landing"],
          "(first equal index:", info["equal_key_indices"][0], ")")
    print("  find_node == bisect_left? ", info["landing_is_first"],
          "-> find_all's back-scan is what returns the full run")
    print("  all-caps indexed query hits:", info["case_changed_hits"],
          "(collation equivalence on indexed columns)")
    print("  + non-indexed Day204=4 hits:", info["non_index_filtered_hits"],
          "(Python == filter on a later column)")
    print()


if __name__ == "__main__":
    main()

"""Read-only migration inventory for a LOCAL CEO checkout; this is not DDT runtime code.

Prints file hashes and Python import names. Never writes to, imports from,
executes, or copies source files out of the CEO project.
"""
from __future__ import annotations

import argparse
import ast
import hashlib
import json
from pathlib import Path

CANDIDATES = (
    "replacement/src/ceo_state/compare.py",
    "replacement/src/ceo_state/loader.py",
    "replacement/src/ceo_state/model.py",
    "replacement/src/ceo_resources/text.py",
    "analysis/scripts/structured_analysis.py",
    "analysis/scripts/phase17-1-cartography.py",
    "analysis/scripts/phase18_3_packet.py",
    "analysis/scripts/phase18_4_packet.py",
    "analysis/scripts/phase18_5_packet.py",
    "analysis/state/state-memory-map.json",
    "analysis/state/cj-alias-dataflow.json",
)


def inventory(root: Path) -> dict:
    if not root.is_dir() or root.is_symlink():
        raise ValueError("source must be an existing, non-symlink directory")
    items = []
    for relative in CANDIDATES:
        source = root / relative
        row = {"path": relative, "state": "missing"}
        if source.is_symlink():
            row["state"] = "symlink-skipped"
        elif source.is_file():
            data = source.read_bytes()
            row.update(state="present", bytes=len(data), sha256=hashlib.sha256(data).hexdigest())
            if source.suffix == ".py":
                try:
                    parsed = ast.parse(data, filename=relative)
                    imports = set()
                    for node in ast.walk(parsed):
                        if isinstance(node, ast.Import):
                            imports.update(alias.name for alias in node.names)
                        elif isinstance(node, ast.ImportFrom):
                            imports.add("." * node.level + (node.module or ""))
                    row["declared_imports"] = sorted(imports)
                except (SyntaxError, UnicodeError) as exc:
                    row["parse_issue"] = str(exc)
        items.append(row)
    return {"schema": "ddt.ceo-migration-inventory.v1", "purpose": "read-only source audit, not portability verdict",
            "candidates": items}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("checkout", type=Path, help="Path to a locally available CEO source checkout")
    args = parser.parse_args()
    print(json.dumps(inventory(args.checkout), sort_keys=True, indent=2))


if __name__ == "__main__":
    main()

from __future__ import annotations

import json
import os
from pathlib import Path


def assert_matches_snapshot(name: str, data: dict):
    snapshot_path = Path(__file__).parent / "snapshots" / f"{name}.json"
    snapshot_path.parent.mkdir(parents=True, exist_ok=True)

    update = os.getenv("UPDATE_SNAPSHOTS", "0") == "1"

    if update or not snapshot_path.exists():
        snapshot_path.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n")
        if not update:
            raise AssertionError(
                f"Snapshot {name} created. Re-run with UPDATE_SNAPSHOTS=1 to accept it."
            )
        return

    expected = json.loads(snapshot_path.read_text())
    assert data == expected, f"Snapshot mismatch for {name}"

"""CLI entrypoint for the hourly sync job (run via cron / scheduler).

    python run_sync.py            # sync both advanced sources into $OFAC_DATA_DIR

Intended to run hourly. It is safe to run concurrently with the API: promotion is
atomic (``os.replace``) and the API hot-reloads on mtime change.
"""

from __future__ import annotations

import json
import os
from datetime import datetime, timezone

from app.sync import sync_all


def main() -> None:
    data_dir = os.environ.get("OFAC_DATA_DIR", "data")
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    outcomes = sync_all(data_dir=data_dir, timestamp=timestamp)
    print(json.dumps({"timestamp": timestamp, "outcomes": outcomes}, indent=2))


if __name__ == "__main__":
    main()

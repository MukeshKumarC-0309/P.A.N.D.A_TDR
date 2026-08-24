"""Export a durable snapshot of the current Splunk data to a local fixture.

Phase 2.1/2.2 support: once exported, the whole detection pipeline can run with
the lab VMs shut down — only the Splunk *source* is replaced by this file.

The fixture stores the RAW rows each pull returns (dicts, exactly as run_search
yields them, multivalue fields included), so the existing structuring and
detection code consumes it unchanged. Re-run this only when you want a fresh
snapshot after generating new lab data.

Run (Splunk tunnel up):  .venv\\Scripts\\python.exe scripts\\export_snapshot.py
"""

import json
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))

from dotenv import load_dotenv

load_dotenv()

from panda_tdr.splunk_client import (
    get_account_creations_raw,
    get_cowrie_events_raw,
    get_failed_logins_raw,
    get_service,
    get_successful_logons_raw,
)

OUT = pathlib.Path(__file__).resolve().parent.parent / "test_data" / "splunk_snapshot.json"


def main():
    service = get_service()
    snapshot = {
        "cowrie": get_cowrie_events_raw(service=service),
        "failed_logins": get_failed_logins_raw(service=service),
        "successful_logons": get_successful_logons_raw(service=service),
        "account_creations": get_account_creations_raw(service=service),
    }
    OUT.write_text(json.dumps(snapshot, indent=2, default=str), encoding="utf-8")
    for key, rows in snapshot.items():
        print(f"  {key}: {len(rows)} rows")
    print(f"saved -> {OUT}")


if __name__ == "__main__":
    main()

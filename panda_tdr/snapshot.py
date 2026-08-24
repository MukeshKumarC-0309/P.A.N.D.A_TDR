"""Offline source — load the exported Splunk snapshot into structured records.

The lab-off counterpart to cowrie_source / windows_source: instead of pulling
live from Splunk, it reads the fixture written by scripts/export_snapshot.py and
runs the SAME structuring functions, so it returns identical record types
(CowrieRecord / WindowsRecord) plus the raw 4720 rows. Every downstream layer
(correlation, detections, reporter) consumes this unchanged — only the source
is swapped from Splunk to a file.

Use this to run the pipeline (and Phase 2.6's incident report) with all lab VMs
shut down. Refresh the fixture with export_snapshot.py after generating new data.
"""

import json
import pathlib

from panda_tdr.cowrie_records import structure_cowrie_events
from panda_tdr.windows_records import structure_failed_logins, structure_successful_logins

DEFAULT_SNAPSHOT = pathlib.Path(__file__).resolve().parent.parent / "test_data" / "splunk_snapshot.json"


def load_snapshot(path=DEFAULT_SNAPSHOT):
    """Load the snapshot fixture and return the pipeline's four inputs.

    Returns a dict:
      cowrie          list[CowrieRecord]
      failed          list[WindowsRecord]  (4625)
      success         list[WindowsRecord]  (4624 Type 3)
      creation_rows   list[dict]           (raw 4720 rows; detect_account_creations consumes rows)

    The account-creation side stays raw because detect_account_creations does the
    creator/built-in filtering itself — mirroring how the live path feeds it raw
    Splunk rows, not pre-structured records.
    """
    data = json.loads(pathlib.Path(path).read_text(encoding="utf-8"))
    return {
        "cowrie": structure_cowrie_events(data["cowrie"]),
        "failed": structure_failed_logins(data["failed_logins"]),
        "success": structure_successful_logins(data["successful_logons"]),
        "creation_rows": data["account_creations"],
    }

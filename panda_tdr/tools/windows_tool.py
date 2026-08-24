"""CrewAI tool wrapping the Windows Event Log source.

Thin adapter between get_windows_records (splunk pull + structure) and a CrewAI
agent. It imports the source and calls it — it never reimplements the pull or
the structuring. All it adds is serialization of the WindowsRecords into text
the LLM can read, and turning connection failures into readable data.
"""

import json
from dataclasses import asdict

from crewai.tools import tool

from panda_tdr.windows_source import get_windows_records
from panda_tdr.tools.windows_summary import summarize_failed_logins


@tool("Pull Windows failed-login events")
def get_windows_failed_logins(earliest: str = "-90d") -> str:
    """Pull Windows failed-login (Event ID 4625) events from Splunk.

    `earliest` is a Splunk time modifier bounding the search (default "-90d";
    the lab data is historical so a wide window is required). Returns a JSON
    object:

        {
          "total_events": <count>,
          "records": [ {timestamp, event_id, src_ip, username}, ... ]
        }

    Each record is one failed logon with its source IP and the target username.
    Noise is NOT filtered out (machine accounts ending in '$', localhost sources
    like ::1 / 127.0.0.1) — excluding those is the correlation stage's job.
    src_ip or username may be null when the source event lacked them.
    """
    try:
        records = get_windows_records(earliest=earliest)
    except Exception as e:
        # Return the failure as data (e.g. Splunk unreachable / auth error) so
        # the agent can read it rather than the crew crashing.
        return json.dumps({"error": f"Splunk pull failed: {type(e).__name__}: {e}"})

    payload = {
        "total_events": len(records),
        "records": [asdict(r) for r in records],
    }
    return json.dumps(payload)


@tool("Summarize Windows failed logins by source IP and username")
def summarize_windows_failed_logins(earliest: str = "-90d") -> str:
    """Pull Windows failed logins (4625) and group them by source IP + username.

    `earliest` is a Splunk time modifier bounding the search (default "-90d").
    Returns a JSON object with one summary per (source IP, targeted account):

        {
          "total_events": <count>,
          "group_count": <distinct (src_ip, username) pairs>,
          "groups": [
            {
              "src_ip", "username", "attempt_count",
              "first_seen", "last_seen", "span_seconds", "hosts": [...]
            }, ...
          ]
        }

    attempt_count across all groups sums to total_events — every attempt is
    accounted for, nothing filtered. Noise (machine '$' accounts, localhost) is
    left in on purpose; excluding it is the correlation stage's job. Prefer this
    tool for a clean per-attacker view of failed-login activity.
    """
    try:
        records = get_windows_records(earliest=earliest)
    except Exception as e:
        return json.dumps({"error": f"Splunk pull failed: {type(e).__name__}: {e}"})

    groups = summarize_failed_logins(records)
    payload = {
        "total_events": len(records),
        "group_count": len(groups),
        "groups": groups,
    }
    return json.dumps(payload)

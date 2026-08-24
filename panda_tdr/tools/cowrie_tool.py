"""CrewAI tool wrapping the standalone cowrie_detector parser.

This is the thin adapter between the framework-agnostic detector and a CrewAI
agent. It IMPORTS cowrie_detector and calls it — it never reimplements parsing
(Repo Structure rule: the Cowrie Crew imports the package, it does not duplicate
its logic). All the tool adds is (1) the file I/O the parser deliberately avoids
and (2) serialization of the structured records into text the LLM can read.
"""

import json
from dataclasses import asdict

from crewai.tools import tool

from cowrie_detector import parse_lines

from .session_summary import summarize_sessions


@tool("Parse Cowrie honeypot log")
def parse_cowrie_log(log_path: str) -> str:
    """Parse a Cowrie SSH-honeypot JSON log file into structured events.

    Pass the path to a Cowrie log file (one JSON event per line). Returns a JSON
    object with the parse summary and every parsed event:

        {
          "total_events": <lines read>,
          "parsed": <events successfully parsed>,
          "skipped": <unparseable lines>,
          "records": [ {session, eventid, src_ip, username, timestamp, ...}, ... ]
        }

    Each record's eventid distinguishes the outcome (cowrie.login.success,
    cowrie.login.failed, cowrie.command.input, ...). username is null on events
    that carry no username (e.g. command.input). Use this to inspect honeypot
    activity: failed vs successful logins, source IPs, and commands run.
    """
    try:
        with open(log_path, encoding="utf-8") as f:
            records, skipped = parse_lines(f)
    except FileNotFoundError:
        # Return the error as data, not an exception, so the agent can read it
        # and react rather than the whole crew crashing.
        return json.dumps({"error": f"log file not found: {log_path}"})

    payload = {
        "total_events": len(records) + skipped,
        "parsed": len(records),
        "skipped": skipped,
        "records": [asdict(r) for r in records],
    }
    return json.dumps(payload)


@tool("Summarize Cowrie honeypot log by session")
def summarize_cowrie_sessions(log_path: str) -> str:
    """Parse a Cowrie log file and group its events into per-session summaries.

    Pass the path to a Cowrie log file (one JSON event per line). Returns a JSON
    object with one summary per SSH session:

        {
          "total_events": <events parsed>,
          "session_count": <distinct sessions>,
          "skipped": <unparseable lines>,
          "sessions": [
            {
              "session", "src_ip", "username",
              "login_success_count", "login_failed_count",
              "commands": [...], "event_count",
              "start", "end", "duration_seconds"
            }, ...
          ]
        }

    login_success_count and login_failed_count are kept separate so a
    "failed, failed, success" brute-force pattern stays visible. Every event is
    accounted for (sum of event_count == total_events) — nothing is filtered.
    Prefer this tool for a clean per-session view of honeypot activity.
    """
    try:
        with open(log_path, encoding="utf-8") as f:
            records, skipped = parse_lines(f)
    except FileNotFoundError:
        return json.dumps({"error": f"log file not found: {log_path}"})

    sessions = summarize_sessions(records)
    payload = {
        "total_events": len(records),
        "session_count": len(sessions),
        "skipped": skipped,
        "sessions": sessions,
    }
    return json.dumps(payload)

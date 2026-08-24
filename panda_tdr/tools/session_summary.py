"""Deterministic per-session summarization of parsed Cowrie events.

Pure logic, no CrewAI: takes CowrieRecords, groups them by session, and returns
structured per-session summaries. This is intentionally deterministic code, not
LLM reasoning — grouping must be lossless (every event accounted for), and the
false-negative-averse design forbids silently dropping events. An LLM is not a
reliable place for exhaustive, lossless enumeration; this is.

It records everything and judges nothing. Whether a session is noise or a real
attack is decided later, by the correlation layer (Phase 1.5).
"""

from collections import OrderedDict
from datetime import datetime


def summarize_sessions(records):
    """Group CowrieRecords by session into per-session summary dicts.

    Returns a list of summaries in order of each session's first appearance.
    login_success_count / login_failed_count are kept separate (not collapsed
    into one outcome) so a "failed, failed, success" brute-force pattern stays
    visible for the correlation layer.
    """
    sessions = OrderedDict()

    for r in records:
        s = sessions.get(r.session)
        if s is None:
            s = {
                "session": r.session,
                "src_ip": r.src_ip,
                "username": None,
                "login_success_count": 0,
                "login_failed_count": 0,
                "commands": [],
                "event_count": 0,
                "_timestamps": [],
            }
            sessions[r.session] = s

        s["event_count"] += 1
        s["_timestamps"].append(r.timestamp)

        # username only appears on login events; keep it when we see it.
        if r.username is not None:
            s["username"] = r.username

        if r.eventid == "cowrie.login.success":
            s["login_success_count"] += 1
        elif r.eventid == "cowrie.login.failed":
            s["login_failed_count"] += 1
        elif r.eventid == "cowrie.command.input":
            # message is like "CMD: whoami"; strip the prefix for a clean command.
            s["commands"].append((r.message or "").removeprefix("CMD: "))

    summaries = []
    for s in sessions.values():
        stamps = sorted(s.pop("_timestamps"))
        start, end = stamps[0], stamps[-1]
        duration = (datetime.fromisoformat(end) - datetime.fromisoformat(start)).total_seconds()
        s["start"] = start
        s["end"] = end
        s["duration_seconds"] = round(duration, 3)
        summaries.append(s)

    return summaries

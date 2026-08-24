"""Deterministic grouping of Windows failed-login records.

Pure logic, no CrewAI and no Splunk: takes WindowsRecords, groups them by
(source IP, username) into per-pair summaries. Same discipline as the Cowrie
session summary — lossless group-by must be deterministic code, not LLM
reasoning (false-negative-averse: every attempt is accounted for).

It records everything and judges nothing; whether a pair is noise or a real
attack is decided later, by the correlation layer (Phase 1.5).
"""

from collections import OrderedDict
from datetime import datetime


def summarize_failed_logins(records):
    """Group WindowsRecords by (src_ip, username) into per-pair summary dicts.

    Returns a list of summaries in order of each pair's first appearance. Each
    summary is one (source IP, targeted account) pair — the granularity that
    maps onto the correlation layer's IP-primary / username-fallback keys — with
    its attempt_count, time span (first_seen/last_seen/span_seconds), and the
    host(s) attacked. attempt_count across all summaries sums to len(records).
    """
    groups = OrderedDict()

    for r in records:
        key = (r.src_ip, r.username)
        g = groups.get(key)
        if g is None:
            g = {
                "src_ip": r.src_ip,
                "username": r.username,
                "attempt_count": 0,
                "hosts": set(),
                "_timestamps": [],
            }
            groups[key] = g

        g["attempt_count"] += 1
        if r.host is not None:
            g["hosts"].add(r.host)
        g["_timestamps"].append(r.timestamp)

    summaries = []
    for g in groups.values():
        stamps = sorted(g.pop("_timestamps"))
        first, last = stamps[0], stamps[-1]
        span = (datetime.fromisoformat(last) - datetime.fromisoformat(first)).total_seconds()
        g["first_seen"] = first
        g["last_seen"] = last
        g["span_seconds"] = round(span, 3)
        g["hosts"] = sorted(g["hosts"])  # set -> stable sorted list for JSON
        summaries.append(g)

    return summaries

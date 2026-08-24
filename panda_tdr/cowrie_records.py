"""Structure raw Splunk rows into CowrieRecords for the live pipeline.

Phase 2.1 Step 2. The standalone cowrie_detector parser (CowrieRecord +
parse_lines) stays the source of truth for the FILE-based path and the
standalone CLI artifact; it is IMPORTED here, never reimplemented (Repo
Structure rule). This module adds the SECOND source path: mapping the dicts a
Splunk pull returns (splunk_client.get_cowrie_events_raw) into that same
CowrieRecord shape, so the correlation layer consumes one record type
regardless of source.

Kept free of the Splunk SDK (exactly like windows_records.py) so the mapping is
unit-testable with plain dicts — no network required.

Two Step-1 discoveries are baked in here:
  * timestamp = Splunk `_time`, NOT the raw `timestamp` field. Splunk returns the
    JSON `timestamp` as a multivalue polluted with a literal 'none'
    (['..Z','none']); `_time` is clean, single-valued, TZ-normalized to +00:00,
    and consistent with the Windows side (which also keys on _time).
  * the extracted fields only come back when explicitly | table'd — handled in
    the SPL (splunk_client.COWRIE_RAW_SPL).
"""

from cowrie_detector import CowrieRecord

# The required set the standalone parser enforces, keyed on the Splunk column
# names (its `timestamp` maps to Splunk `_time`, guaranteed present, so it isn't
# listed here). A row missing any of these can't be placed in a session or
# correlated, so it's dropped rather than admitted half-empty — mirrors
# cowrie_detector.parser.REQUIRED_FIELDS and its false-negative-averse stance.
_REQUIRED = ("session", "eventid", "src_ip")


def _clean(value):
    """Normalize one Splunk value.

    '-', '', 'none' and None all collapse to None (Splunk renders a null field
    variously as '-' or the literal string 'none'). A multivalue list collapses
    to its first meaningful entry — defensive: we key on the single-valued _time,
    not the polluted `timestamp`, but a surprise multivalue username/message
    shouldn't crash the mapping.
    """
    if isinstance(value, list):
        for v in value:
            cleaned = _clean(v)
            if cleaned is not None:
                return cleaned
        return None
    return value if value not in (None, "-", "", "none") else None


def _int_or_none(value):
    """Coerce a Splunk numeric column (returned as a string, e.g. '54800') to int.

    CowrieRecord types src_port as Optional[int] (the file parser gets it as a
    JSON int); this keeps the contract identical across both source paths.
    Tolerates missing/junk as None rather than raising.
    """
    value = _clean(value)
    try:
        return int(value) if value is not None else None
    except (TypeError, ValueError):
        return None


def structure_cowrie_events(rows):
    """Map raw Splunk cowrie dicts into CowrieRecords.

    `rows` is splunk_client.get_cowrie_events_raw() output — each dict carries
    _time plus the | table'd cowrie fields. Rows missing a required field
    (session/eventid/src_ip) are skipped, matching the standalone parser's rule
    of never admitting a half-empty record. Returns list[CowrieRecord], the same
    shape the file-based parser yields, so downstream is source-agnostic.

    dst_ip / dst_port / sensor are left at their defaults (None): they're pure
    context, unused downstream, so they're not tabled or mapped — same
    "table only what's needed" discipline as the Windows pull.
    """
    records = []
    for row in rows:
        if not all(_clean(row.get(field)) is not None for field in _REQUIRED):
            continue
        records.append(
            CowrieRecord(
                session=_clean(row["session"]),
                eventid=_clean(row["eventid"]),
                src_ip=_clean(row["src_ip"]),
                timestamp=row["_time"],  # Step-1 decision: _time, not raw `timestamp`
                username=_clean(row.get("username")),
                src_port=_int_or_none(row.get("src_port")),
                password=_clean(row.get("password")),
                message=_clean(row.get("message")),
            )
        )
    return records

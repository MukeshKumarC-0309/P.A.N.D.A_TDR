"""Phase 1.5 Step 7 — the full correlation pipeline, end to end.

Cowrie records + Windows records -> join -> IP-primary matches -> assemble
per-identity inputs -> decision tree (severity) -> output contract
{severity, narrative, recommended_action}.

Cowrie is read from a file (COWRIE_LOG); Windows is pulled live from Splunk
through get_service's capped-exponential backoff (rides out the flaky auth).
"""

import json
import pathlib
import sys

# Make the project root importable (for panda_tdr) no matter where this is launched from.
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))

from dotenv import load_dotenv

load_dotenv()
sys.stdout.reconfigure(encoding="utf-8")

from cowrie_detector import parse_lines
from panda_tdr import correlation as corr
from panda_tdr.alerting import build_alert
from panda_tdr.severity_model import train_severity_tree
from panda_tdr.windows_source import get_windows_records

COWRIE_LOG = r"C:\PANDA_TDR\test_data\cowrie.json"


def run(cowrie_records, windows_records):
    """Records in -> (alerts, match counts). Runs BOTH correlation paths:
    IP-primary (same-IP, high/medium tier) and username-fallback (same account
    across different IPs, LOW tier, deny-listed)."""
    frame = corr.build_correlation_frame(cowrie_records, windows_records)

    ip_matches = corr.match_ip_primary(frame)
    ip_inputs = corr.assemble_agent_inputs(ip_matches, cowrie_records)

    uf_matches = corr.apply_deny_list(
        corr.match_username_fallback(cowrie_records, windows_records)
    )
    uf_inputs = corr.assemble_username_fallback_inputs(uf_matches, cowrie_records)

    clf = train_severity_tree(max_depth=3)
    inputs = ip_inputs + uf_inputs
    counts = {"ip_matches": len(ip_matches), "username_fallback_matches": len(uf_matches)}
    return [build_alert(i, clf) for i in inputs], counts


def main():
    with open(COWRIE_LOG, encoding="utf-8") as f:
        cowrie, _ = parse_lines(f)
    windows = get_windows_records()

    alerts, counts = run(cowrie, windows)
    print(f"cowrie={len(cowrie)} windows={len(windows)} "
          f"ip_matches={counts['ip_matches']} username_fallback_matches={counts['username_fallback_matches']} "
          f"correlated_identities={len(alerts)}\n")
    for alert in alerts:
        print(json.dumps(alert, indent=2))
    if not alerts:
        print("(no correlated identities in current data)")


if __name__ == "__main__":
    main()

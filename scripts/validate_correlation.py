"""Run correlation Steps 1-4 on a FRESH Cowrie export + live Windows Splunk data.

Use after generate_test_attack.sh to confirm a real, time-overlapping positive
match — not just synthetic data. Cowrie is read from a file (point COWRIE_LOG at
the fresh export); Windows is pulled live from Splunk (through get_service's
backoff, so it rides out the flaky auth).

load_dotenv() first: the Splunk client reads SPLUNK_* at import time.
"""

import sys
import pathlib

# Make the project root importable (for panda_tdr) no matter where this is launched from.
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))

from dotenv import load_dotenv

load_dotenv()
sys.stdout.reconfigure(encoding="utf-8")

from cowrie_detector import parse_lines
from panda_tdr import correlation as corr
from panda_tdr.windows_source import get_windows_records

# ---- point this at the FRESH Cowrie export (JSON, one event per line) ----
COWRIE_LOG = r"C:\PANDA_TDR\test_data\cowrie.json"
# --------------------------------------------------------------------------

HIGH_MAX_SECONDS = 180  # IP match 0-3 min = HIGH; 3-5 min = MEDIUM (locked spec)


def main():
    with open(COWRIE_LOG, encoding="utf-8") as f:
        cowrie, skipped = parse_lines(f)
    print(f"Cowrie : {len(cowrie)} records ({skipped} skipped) from {COWRIE_LOG}")

    windows = get_windows_records()  # live from Splunk, with backoff
    print(f"Windows: {len(windows)} records (live from Splunk)")

    merged = corr.build_correlation_frame(cowrie, windows)
    ip_matches = corr.match_ip_primary(merged)
    uf_matches = corr.apply_deny_list(corr.match_username_fallback(cowrie, windows))

    print(f"\nIP-primary matches (<= 5 min): {len(ip_matches)}")
    for _, r in ip_matches.iterrows():
        dt = r["time_delta_seconds"]
        tier = "HIGH" if dt <= HIGH_MAX_SECONDS else "MEDIUM"
        print(
            f"  [{tier}] src_ip={r['src_ip']} "
            f"cowrie_user={r['cowrie_username']} win_user={r['windows_username']} "
            f"delta={dt:.0f}s  cowrie_ts={r['cowrie_timestamp']} win_ts={r['windows_timestamp']}"
        )

    print(f"\nusername-fallback matches (<= 3 min, different IP, post deny-list): {len(uf_matches)}")
    for _, r in uf_matches.iterrows():
        print(
            f"  user={r['norm_username']} cowrie_ip={r['cowrie_src_ip']} "
            f"win_ip={r['windows_src_ip']} delta={r['time_delta_seconds']:.0f}s"
        )

    if len(ip_matches) == 0 and len(uf_matches) == 0:
        print(
            "\nNo matches. If you just ran an attack, check: same src_ip on both sides, "
            "hits within the window, and COWRIE_LOG points at the FRESH export (not the "
            "stale test_data)."
        )


if __name__ == "__main__":
    main()

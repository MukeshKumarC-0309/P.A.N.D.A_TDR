"""Run the WHOLE PANDA TDR pipeline in one command.

    Cowrie + Windows failed-logins (BOTH live from Splunk, one connection)
      -> correlation (IP-primary + username-fallback, deny-list, tiered windows)
      -> interpretable severity tree
      -> deterministic honest alert card
      -> Gemini Reporter polish
      -> one final human-readable report per correlated identity.

Phase 2.1: Cowrie is already indexed in Splunk (index=main sourcetype=_json), so
both sources are a single live pull — no manual test_data/cowrie.json export.

Prerequisites:
  - .env has GEMINI_API_KEY, SPLUNK_USER, SPLUNK_PASSWORD (host/port default localhost:8089)
  - the Splunk port-forward is up (localhost:8089) and the Windows forwarder is shipping

Run:  .venv\\Scripts\\python.exe scripts\\run_all.py
"""

import sys
import pathlib

# Make the project root importable (for panda_tdr) no matter where this is launched from.
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))

from dotenv import load_dotenv

load_dotenv()  # must precede panda_tdr imports (llm.py / splunk read env at import)
sys.stdout.reconfigure(encoding="utf-8")
sys.stderr.reconfigure(encoding="utf-8")

from crewai import Crew

from panda_tdr import correlation as corr
from panda_tdr.alerting import score, _RECOMMENDED_ACTION
from panda_tdr.cowrie_source import get_cowrie_records
from panda_tdr.crews.reporter_crew import polish_alert_task, reporter_agent
from panda_tdr.detections import (
    assess_severity,
    detect_account_creations,
    detect_failed_login_attacks,
    detect_multistage_chains,
)
from panda_tdr.polish_guard import guarded_polish
from panda_tdr.reporter import (
    render_account_creation_alert,
    render_alert,
    render_chain_alert,
    render_detection_alert,
)
from panda_tdr.severity_model import train_severity_tree
from panda_tdr.splunk_client import (
    get_account_creations_raw,
    get_service,
    get_successful_logons_raw,
)
from panda_tdr.windows_records import structure_successful_logins
from panda_tdr.windows_source import get_windows_records


def assemble_inputs(cowrie_records, windows_records):
    """Run BOTH correlation paths and return one input per correlated identity."""
    frame = corr.build_correlation_frame(cowrie_records, windows_records)

    ip_inputs = corr.assemble_agent_inputs(corr.match_ip_primary(frame), cowrie_records)

    uf_matches = corr.apply_deny_list(
        corr.match_username_fallback(cowrie_records, windows_records)
    )
    uf_inputs = corr.assemble_username_fallback_inputs(uf_matches, cowrie_records)

    return ip_inputs + uf_inputs


def polish(card):
    """Gemini rewrites only the wording of the finished card."""
    crew = Crew(agents=[reporter_agent], tasks=[polish_alert_task], verbose=False)
    return str(crew.kickoff(inputs={"card": card}))


def polish_guarded(card, severity):
    """Polish the deterministic card, but SHIP THE CARD if the polish fails or drifts.

    guarded_polish degrades in both directions: if the LLM call raises (API down,
    rate-limited, no key) or the rewrite drifts (LaTeX, dropped severity,
    dropped/invented IP), the deterministic card — always correct — ships instead.
    So one dependency hiccup can't crash the run, and a bad rewrite can't reach an
    alert.
    """
    text, reason = guarded_polish(card, severity, polish)
    if reason:
        print(f"[!] {reason}; shipping the deterministic card.")
    return text


def emit(label, report, severity):
    """Print one alert with the deterministic severity as authoritative."""
    print(f"===== {label}  [severity={severity}] =====")
    print(report)
    print()


def main():
    # 1) load both sources — BOTH live from Splunk now (Phase 2.1). Cowrie is
    # already indexed (index=main sourcetype=_json), so one connection, shared
    # across both pulls, replaces the old manual test_data/cowrie.json export.
    try:
        service = get_service()  # one connection, with backoff
        cowrie = get_cowrie_records(service=service)
        windows = get_windows_records(service=service)
        creation_rows = get_account_creations_raw(service=service)  # 4720
        successes = structure_successful_logins(get_successful_logons_raw(service=service))  # 4624 T3
    except Exception as e:
        print(f"[!] Live Splunk pull failed ({type(e).__name__}). Is the tunnel up "
              "(localhost:8089) and the Windows forwarder shipping? Splunk auth is "
              "intermittently flaky — re-running usually works.")
        raise SystemExit(1)
    print(f"[*] Cowrie : {len(cowrie)} records (live from Splunk)")
    print(f"[*] Windows: {len(windows)} records (live from Splunk)")

    clf = train_severity_tree(max_depth=3)

    # 2) CROSS-SOURCE correlation alerts (Cowrie <-> Windows, one per identity)
    inputs = assemble_inputs(cowrie, windows)
    print(f"[*] Correlated identities: {len(inputs)}")
    for n, inp in enumerate(inputs, 1):
        severity, _ = score(inp, clf)               # deterministic = authoritative
        report = polish_guarded(render_alert(inp, clf), severity)
        emit(f"CORRELATION ALERT {n}/{len(inputs)}", report, severity)

    # 3) STANDALONE detections (single-source: 4625 brute-force / password-spray).
    # Reuses the Windows records already pulled — no extra Splunk call. Runs
    # regardless of whether anything correlated: a single-surface attack is
    # exactly what these detectors exist to catch.
    detections = detect_failed_login_attacks(windows)
    print(f"[*] Failed-login detections: {len(detections)}")
    for n, det in enumerate(detections, 1):
        severity = assess_severity(det)              # deterministic = authoritative
        report = polish_guarded(render_detection_alert(det), severity)
        emit(f"{det.detection_type.upper()} DETECTION {n}/{len(detections)}", report, severity)

    # 4) ACCOUNT-CREATION detections (4720). System/OS-created accounts are
    # filtered out in the detector; only real-session creations survive -> HIGH.
    creations = detect_account_creations(creation_rows)
    print(f"[*] Account-creation detections: {len(creations)}")
    for n, det in enumerate(creations, 1):
        report = polish_guarded(render_account_creation_alert(det), det.severity)
        emit(f"ACCOUNT-CREATION DETECTION {n}/{len(creations)}", report, det.severity)

    # 5) MULTI-STAGE kill chains (failed -> success -> persistence). Stitches the
    # failed logons, successful network logons, and account creations into a
    # confirmed-compromise narrative — the most severe pattern the system emits.
    chains = detect_multistage_chains(windows, successes, creations)
    print(f"[*] Multi-stage chains: {len(chains)}")
    for n, chain in enumerate(chains, 1):
        report = polish_guarded(render_chain_alert(chain), chain.severity)
        emit(f"MULTI-STAGE CHAIN {n}/{len(chains)}", report, chain.severity)

    if not inputs and not detections and not creations and not chains:
        print("Nothing to report in the current data — no correlated identities and no "
              "standalone detections tripped their thresholds.")


if __name__ == "__main__":
    main()

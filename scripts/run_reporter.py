"""Phase 1.6 Step 4 — end-to-end to a final polished report on one real case.

Chain: records -> correlation -> tree -> deterministic card (render_alert) ->
Reporter crew (Gemini polishes the WORDING only) -> final report.

The deterministic severity/recommended_action stay AUTHORITATIVE (re-stamped
here); the LLM prose is presentation. A light post-check confirms the polished
text still carries the severity and the logon-type caveat.
"""

import sys
import pathlib

# Make the project root importable (for panda_tdr) no matter where this is launched from.
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))

from dotenv import load_dotenv

load_dotenv()
sys.stdout.reconfigure(encoding="utf-8")
sys.stderr.reconfigure(encoding="utf-8")

from types import SimpleNamespace as R

from crewai import Crew

from panda_tdr import correlation as corr
from panda_tdr.alerting import score
from panda_tdr.crews.reporter_crew import polish_alert_task, reporter_agent
from panda_tdr.reporter import render_alert
from panda_tdr.severity_model import train_severity_tree


def polish(agent_input, clf):
    card = render_alert(agent_input, clf)
    crew = Crew(agents=[reporter_agent], tasks=[polish_alert_task], verbose=False)
    polished = str(crew.kickoff(inputs={"card": card}))
    severity, action = score(agent_input, clf)  # deterministic = authoritative
    return card, polished, severity, action


def main():
    clf = train_severity_tree(max_depth=3)

    # The real 08-04 pair (reconstructed from confirmed observed values).
    cowrie = [
        R(src_ip="10.0.2.3", username="admin", timestamp="2026-08-04T12:24:58.169Z", eventid="cowrie.login.failed", message="x"),
        R(src_ip="10.0.2.3", username=None, timestamp="2026-08-04T12:24:58.18Z", eventid="cowrie.command.input", message="CMD: exit"),
    ]
    windows = [
        R(src_ip="10.0.2.3", username="bmleg", timestamp="2026-08-04T17:54:57.001+05:30", event_id="4625", host="DESKTOP-G38AOOL", logon_type="3"),
    ]
    inp = corr.assemble_agent_inputs(corr.match_ip_primary(corr.build_correlation_frame(cowrie, windows)), cowrie)[0]

    card, polished, severity, action = polish(inp, clf)

    print("===== DETERMINISTIC CARD (source of truth) =====")
    print(card)
    print("\n===== LLM-POLISHED REPORT =====")
    print(polished)
    print("\n===== AUTHORITATIVE (deterministic, re-stamped) =====")
    print(f"severity: {severity} | recommended_action: {action}")
    print("\n===== HONESTY POST-CHECK =====")
    p = polished.lower()
    print(f"  polished mentions severity '{severity}':", severity.lower() in p)
    print("  preserves logon-type caveat:",
          "logon" in p and any(s in p for s in ("did not", "didn't", "not affect", "not influence")))


if __name__ == "__main__":
    main()

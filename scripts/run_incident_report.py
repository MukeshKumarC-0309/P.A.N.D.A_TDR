"""Generate the incident report for the eviluser kill chain (Phase 2.6).

Runs FULLY OFFLINE from the snapshot fixture (no Splunk, lab VMs off):
  snapshot -> multi-stage chain -> deterministic report sections
  -> Gemini polishes ONLY the prose sections (Executive Summary, Impact)
  -> per-section FACT GUARD reverts any section that lost a hard fact
  -> write reports/incident_<account>.md

Structured sections (tables, timeline, IOCs, MITRE IDs) are never sent to the
LLM, so exact facts and technique IDs can't drift. Needs internet for Gemini.

Run:  .venv\\Scripts\\python.exe scripts\\run_incident_report.py
"""

import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))

from dotenv import load_dotenv

load_dotenv()
sys.stdout.reconfigure(encoding="utf-8")

from crewai import Crew

from panda_tdr.crews.reporter_crew import polish_section_task, reporter_agent
from panda_tdr.detections import detect_account_creations, detect_multistage_chains
from panda_tdr.incident_report import (
    PROSE_SECTIONS,
    layman_sections,
    render_incident_report,
    report_sections,
)
from panda_tdr.snapshot import load_snapshot

OUT_DIR = pathlib.Path(__file__).resolve().parent.parent / "reports"


def polish_section(text):
    crew = Crew(agents=[reporter_agent], tasks=[polish_section_task], verbose=False)
    return str(crew.kickoff(inputs={"section": text}))


def required_facts(chain):
    """Hard facts that MUST survive a polish verbatim (else revert the section)."""
    facts = [chain.src_ip, chain.account, str(chain.failure_count), *chain.created_accounts]
    return [f for f in facts if f]


def guard(section_key, deterministic, polished, facts):
    """Keep the polish only if every hard fact that was in the deterministic
    section is still present; otherwise revert (drift protection)."""
    needed = [f for f in facts if f in deterministic]
    # Impact must also keep its honest-limit keywords, not just the hard facts.
    if section_key == "impact":
        needed += [w for w in ("lateral movement", "exfiltration") if w in deterministic]
    missing = [f for f in needed if f not in polished]
    if missing:
        print(f"    [guard] '{section_key}' reverted to deterministic (lost: {missing})")
        return deterministic
    print(f"    [guard] '{section_key}' polish accepted")
    return polished


def generate_advanced(chain):
    """Full technical report: deterministic facts + Gemini prose polish + fact guard."""
    sections = report_sections(chain)
    facts = required_facts(chain)
    for key in PROSE_SECTIONS:
        print(f"    polishing prose section: {key}")
        polished = polish_section(sections[key])
        sections[key] = guard(key, sections[key], polished, facts)
    return render_incident_report(chain, sections=sections)


def generate_normal(chain):
    """Plain-language report: fully deterministic, no LLM (honesty guaranteed, runs offline)."""
    return render_incident_report(chain, mode="normal")


def main():
    # mode: normal | advanced | both  (default both)
    mode = sys.argv[1].lower() if len(sys.argv) > 1 else "both"
    if mode not in ("normal", "advanced", "both"):
        print(f"Unknown mode '{mode}'. Use: normal | advanced | both")
        raise SystemExit(2)

    snap = load_snapshot()
    creations = detect_account_creations(snap["creation_rows"])
    chains = detect_multistage_chains(snap["failed"], snap["success"], creations)
    if not chains:
        print("No multi-stage chain in the snapshot — nothing to report.")
        return
    chain = chains[0]
    print(f"[*] Incident: {chain.src_ip} cracked '{chain.account}' on {chain.host} "
          f"({chain.stage_count}-stage)")

    OUT_DIR.mkdir(exist_ok=True)
    builders = {"advanced": generate_advanced, "normal": generate_normal}
    for m in (("advanced", "normal") if mode == "both" else (mode,)):
        print(f"[*] Generating {m} report...")
        report = builders[m](chain)
        out_path = OUT_DIR / f"incident_{chain.account}_{m}.md"
        out_path.write_text(report, encoding="utf-8")
        print(f"[*] Wrote {out_path}")


if __name__ == "__main__":
    main()

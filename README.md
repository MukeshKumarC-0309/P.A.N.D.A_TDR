# PANDA TDR — Threat Detection & Response

A multi-source threat-detection pipeline that correlates **SSH-honeypot activity
(Cowrie)** with **Windows Security-log telemetry**, scores it with an
interpretable model, and produces honest, analyst-ready alerts and incident
reports. Built around one principle: **the system says only what the data
supports — confidence is graded and stated, never asserted.**

## What it does

From a single live Splunk pull of both sources, it produces four kinds of finding:

| Detection | Source(s) | Idea |
|---|---|---|
| **Cross-source correlation** | Cowrie ⇄ Windows 4625 | same attacker IP (or account) on the honeypot *and* the endpoint within a time window |
| **Brute-force / password-spray** | Windows 4625 | one IP hammering one account (brute) vs. many accounts shallowly (spray) |
| **Account creation** | Windows 4720 | a new account created by a real (non-system) session — persistence |
| **Multi-stage kill chain** | Windows 4625 → 4624 → 4720 | failed logons → a successful network logon → account creation = a confirmed compromise |

Every finding is rendered as a deterministic **alert card** (facts locked), then
polished into natural prose by an LLM *without* changing any fact, and the full
kill-chain incident is written up as a formal **incident report** in two
audiences: **technical** (MITRE ATT&CK, IOCs, Event IDs) and **plain-language**
(no jargon, call-center-level actions).

## Architecture

```
  Cowrie SSH honeypot ┐                          ┌─ cross-source correlation (shared src_ip / username)
                      ├─► Splunk ─► live pull  ───┤
  Windows Security    ┘   (index=main)            ├─ standalone detections:
    log 4625/4624/4720                            │     • brute-force / password-spray (4625)
                                                  │     • account creation (4720)
                                                  │     • multi-stage kill chain (4625→4624→4720)
                                                  ▼
                              interpretable severity (decision tree)
                                                  ▼
                              deterministic alert card  ──►  LLM prose polish (facts locked)
                                                  ▼
                              dual-audience incident report (technical + plain-language)
```

The correlation and detection layers are **dependency-injected** (records are
passed in, not fetched), which keeps them pure, offline-testable, and free of any
Splunk/LLM dependency.

## Running it

**Setup**
```bash
python -m venv .venv
.venv/Scripts/activate            # Windows;  source .venv/bin/activate on Unix
pip install -r requirements.txt
pip install -e ../cowrie_detector # the standalone Cowrie parser (separate package)
```

Create a `.env` (see the variables below) for the live pipeline and LLM polish:
```
SPLUNK_HOST, SPLUNK_PORT, SPLUNK_USER, SPLUNK_PASSWORD   # live Splunk pull
GEMINI_API_KEY                                           # Reporter prose polish
```

**Full live pipeline** (needs the Splunk tunnel up + forwarder shipping):
```bash
python scripts/run_all.py
```

**Offline — no Splunk, no lab VMs.** A captured snapshot
(`test_data/splunk_snapshot.json`) lets the incident report run entirely from
disk:
```bash
python scripts/run_incident_report.py both   # writes reports/incident_<account>_{advanced,normal}.md
```

**Tests** (pure, offline, no keys required):
```bash
pytest tests/
```

## Layout

```
panda_tdr/
  splunk_client.py       # Splunk REST pulls (Cowrie + 4625/4624/4720)
  cowrie_source.py       # live Cowrie records;  windows_source.py  # live Windows records
  correlation.py         # cross-source join (IP-primary + username fallback, tiered windows)
  detections.py          # brute/spray, account-creation, multi-stage chain
  severity_model.py      # interpretable decision tree (deterministic policy)
  alerting.py / reporter.py           # deterministic alert cards
  incident_report.py     # dual-audience incident report (technical + plain-language)
  crews/                 # CrewAI agents/tasks (LLM prose polish only)
  snapshot.py            # offline source: load the snapshot fixture
scripts/                 # run_all, run_incident_report, export_snapshot, ...
tests/                   # unit tests for the detection/correlation logic
```

## Limitations & honest scope

This is a **lab project**, and the design is deliberate about what it does and
does not prove:

- **Environment.** A single Windows host and a controlled attacker in an isolated
  network. Findings are high-fidelity *in this lab*; production telemetry is noisier.
- **`src_ip` as identity.** Correlating the honeypot to the endpoint on a shared
  source IP is strong here, but weaker in the real world (NAT / CGNAT / VPN / cloud
  egress). Correlation confidence is therefore reported as a **tier**, never as
  certainty — the alerts say "very likely one actor," not "confirmed."
- **Username fallback.** Matching on a shared account across different IPs is
  intentionally lower-confidence: cross-OS namespaces differ (`root` ≠
  `Administrator`) and common names (`admin`) are tried by everyone.
- **Severity model.** The decision tree is a **deterministic policy** trained on a
  tiny, policy-derived set; it recovers that policy by construction. It is a
  **methodology demonstration, not validated generalization** — there is no
  measured false-positive rate yet.
- **Persistence link in the kill chain.** The account-creation stage is linked to
  the breach by **host + timing** (Event 4720 carries no source IP), and is
  flagged as *concurrent persistence on the breached host* — not proof that the
  cracked session itself created the account.
- **Time correlation** assumes reasonably synchronized clocks; all timestamps are
  normalized to UTC at ingest.

These are stated up front on purpose: an alert is only useful if you can trust
exactly what it claims.

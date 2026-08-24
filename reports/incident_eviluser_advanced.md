# Incident Report — Credential Compromise on DESKTOP-G38AOOL

**Report ID:** INC-20260822-10-0-2-3  
**Severity:** HIGH  
**Status:** Confirmed intrusion  
**Affected host:** DESKTOP-G38AOOL  
**Prepared by:** PANDA TDR (automated multi-stage detection)

## 1. Executive Summary

On 2026-08-22 08:38:53 UTC, source `10.0.2.3` achieved a **confirmed compromise** of the local account `eviluser` on `DESKTOP-G38AOOL`. The attacker brute-forced the account with 12 failed attempts, succeeded after ~89 seconds and established persistence by creating `backdoor`. This is a confirmed successful breach, not an attempted one, and warrants immediate incident response.

## 2. Incident Classification

| Field | Value |
| --- | --- |
| Severity | HIGH |
| Type | Brute-force → successful compromise → persistence |
| Confidence | High (failed → success confirmed on same IP + account) |
| Source | `10.0.2.3` |
| Compromised account | `eviluser` |
| Attacker-created account(s) | `backdoor` |
| Host | `DESKTOP-G38AOOL` |
| Detection time | 2026-08-22 08:38:53 UTC |

## 3. Timeline of Events

- **2026-08-22 08:37:25 UTC** — Stage 1: brute-force begins — 12 failed network logons (Event 4625) from `10.0.2.3` against `eviluser`.
- **2026-08-22 08:38:53 UTC** — Stage 2: **breach** — successful network logon (Event 4624, Type 3) as `eviluser` from `10.0.2.3` (~89s after the first attempt).
- **2026-08-22 08:39:43 UTC** — Stage 3: persistence — account `backdoor` created on `DESKTOP-G38AOOL` (created by `bmleg`).

## 4. MITRE ATT&CK Mapping

| Tactic | Technique | Observed |
| --- | --- | --- |
| Initial Access / Credential Access | T1110 — Brute Force | 12 failed logons against `eviluser` |
| Lateral Movement / Initial Access | T1021.002 — Remote Services: SMB/Windows Admin Shares | network (Type 3) logon over SMB/IPC$ |
| Defense Evasion / Persistence | T1078.003 — Valid Accounts: Local Accounts | successful logon using cracked credentials for `eviluser` |
| Persistence | T1136.001 — Create Account: Local Account | created `backdoor` on the host |

## 5. Indicators of Compromise

- **Source IP:** `10.0.2.3`
- **Compromised account:** `eviluser`
- **Attacker-created account(s):** `backdoor`
- **Affected host:** `DESKTOP-G38AOOL`
- **Authentication:** NTLM network logon (Logon Type 3)

## 6. Impact Assessment

- **Confirmed:** The credentials for `eviluser` are compromised, as the attacker authenticated successfully from `10.0.2.3`.
- **Confirmed:** Persistence has been established, with `backdoor` now present on `DESKTOP-G38AOOL`, which would survive a password reset of `eviluser`.
- **Blast radius:** Includes any resource that `eviluser` or the newly created account(s) can reach from `DESKTOP-G38AOOL`.
- **Not yet established (honest limit):** There is no evidence in this data of lateral movement or data exfiltration. However, absence of evidence is not evidence of absence; confirming those activities would require process (4688) and network telemetry that are not covered here.

## 7. Response & Recommendations

**Contain**
- Isolate `DESKTOP-G38AOOL` from the network.
- Block `10.0.2.3` at the perimeter.

**Eradicate**
- Disable/remove `eviluser` and `backdoor`.
- Remove any privileged-group membership granted to these accounts.

**Recover**
- Reset credentials for `eviluser` and any account sharing that password.
- Verify no additional persistence remains (scheduled tasks, services, extra accounts).
- Restore `DESKTOP-G38AOOL` to monitoring and watch for re-compromise from `10.0.2.3`.

## 8. Detection & Evidence Notes

- **How it was detected:** the multi-stage chain detector stitched failed logons (4625), a successful network logon (4624 Type 3), and account creation (4720) into one chain — triggering because ≥ 3 failures preceded a success from the same IP and account.
- **Honest limit — persistence link:** the account creation is linked to the breach by **host and timing** (within 60 min on the same host); Event 4720 carries no source IP, so this is flagged as concurrent persistence on the breached host, not proof the cracked session itself created the account.
- **Honest limit — model:** severity here is a deterministic policy rule, not a statistically validated model; reported detection metrics elsewhere are by-construction and are a methodology demonstration, not generalization evidence.
- **Environment:** single-host lab telemetry via Splunk (Cowrie honeypot + Windows Security log).
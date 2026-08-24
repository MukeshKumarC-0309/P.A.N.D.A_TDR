# PANDA TDR — Build Log & Post-Mortem

A multi-agent Threat Detection & Response (TDR) capability that ingests SSH-honeypot
(Cowrie) and Windows Event Log data, correlates the two sources, scores the result with
an interpretable model, and produces confidence-scored, human-readable alerts.

This document has **two parts**:

- **Part 1 — What We Built** — the delivered work, phase by phase.
- **Part 2 — Problems & Fixes** — every error/blocker we hit, its root cause, and how it
  was rectified, plus the lesson each one taught.

> **A note on phase coverage.** The sections below run in **phase order** — Phase 0, then
> 1.1 → 1.6, then a **Cross-Cutting** section for environment/tooling/lab-operations work
> that spanned every phase.

---
---

# PART 1 — WHAT WE BUILT

## Phase 0 — Lab Infrastructure (pre-existing)

The physical/virtual lab the pipeline runs against.

- **Splunk indexer** on an Ubuntu VM; a **Windows VM** on an isolated NAT network
  (`10.0.2.0/24`) with no exposure to the host network.
- **Splunk Universal Forwarder** on the Windows box shipping four Event IDs — **4624**
  (successful logon), **4625** (failed logon), **4688** (process creation), **4720**
  (account created); **Sysmon** added later for richer telemetry.
- **Cowrie SSH honeypot** installed via `pip install cowrie` (the git-based install was
  abandoned after unresolved issues). Port 22 → 2222 via iptables; real SSH on 2200. JSON
  logs confirmed flowing into Splunk with fields parsing correctly.
- Two validated Splunk searches (a failed-login aggregation and a logon→process
  `transaction`) and a basic dashboard on top.

## Phase 1.1 — Base App & Security Hardening

**Goal:** the existing PANDA application onto which the TDR capability is added, made secure
by design.

- A security-hardening pass established: hashed passwords, **all credentials via environment
  variables from day one**, corrected exception handling, and **no secrets ever committed to
  git history**.
- Publication is planned as one **unified reveal** — the TDR capability released *together
  with* the finished app, not the base app ahead of time.

## Phase 1.2 — Architecture & Correlation Design

**Goal:** lock the architectural decisions the rest of the project builds on, before any
implementation code is written.

- **CrewAI** (hierarchical multi-agent), **not LangGraph** — considered and rejected on its
  merits (both express the same pipeline; the one problem LangGraph would solve,
  guardrail-retry instability, is solvable within CrewAI).
- **`@tool` decorator pattern**, **not MCP** — MCP's process-boundary complexity added no
  value at this stage.
- The **crew layout** — Cowrie Crew, Windows Crew, Correlation Layer, Reporter Agent.
- The **Correlation Design Spec** — IP-primary / username-fallback matching, tiered time
  windows, deny-list, false-negative-averse bias, an interpretable decision tree —
  **pressure-tested against 5 test cases before any implementation code was written**.

## Phase 1.3 — Cowrie Crew

**Goal:** turn raw Cowrie JSON into structured, session-grouped summaries and expose them to
a CrewAI agent — the first, self-contained detection crew.

- **Parser.** `parse_line()` maps one JSON line to a record or `None`; `parse_lines()`
  consumes any iterable of lines and returns `(records, skipped)`. It is deliberately
  **false-negative-averse** — an unparseable line is *counted*, never silently dropped —
  because "unseen data loss" is the exact blind spot the whole system's bias exists to
  prevent.
- **`CowrieRecord`.** A `frozen=True` dataclass — the detector's **public output contract**
  (the shape the standalone CLI *and* the crew both consume). Immutable so nothing
  downstream can mutate a parsed event.
- **Standalone package.** `cowrie_detector/` with its own `pyproject.toml`, a deliberately
  minimal 4-name public API (`parse_line`, `parse_lines`, `CowrieRecord`,
  `REQUIRED_FIELDS`), zero runtime dependencies. Kept **separate from PANDA TDR** so it is a
  distinct, reusable portfolio artifact (a minor standalone project + a major integrated
  system, not one undifferentiated blob). Consumed via `pip install -e`.
- **Real-data test.** A stdlib `unittest` suite run against **37 real captured events** —
  the step that caught the `username` parser bug (Part 2).
- **CrewAI integration.** A `parse_cowrie_log` tool for raw events and a **deterministic**
  `summarize_cowrie_sessions` tool that groups events by SSH session. A `SSH Honeypot
  Session Analyst` agent + task, run end-to-end through Gemini.

**Key design stance — "Option B".** The lossless group-by is done in **deterministic code**,
not by the LLM; the agent only orchestrates and presents. Login outcomes are kept as
**separate success/failed counts** (never collapsed to one "outcome"), so a
*failed → failed → success* brute-force pattern stays visible for the correlation layer.

## Phase 1.4 — Windows Event Log Crew

**Goal:** mirror the Cowrie crew for Windows failed-login telemetry, pulled live from Splunk,
emitting a shape compatible with the Cowrie output.

- **Splunk client** (`splunk_client.py`). `get_service()` connects over the REST API using
  env-var config (`SPLUNK_HOST/PORT/USER/PASSWORD/VERIFY`); `run_search()` runs a oneshot
  search and returns `list[dict]`. Built on the official Splunk Python SDK, reached through
  a `localhost:8089` port-forward.
- **Correlation-ready source.** A **raw, per-event 4625 pull** (`_time`, `Account_Name`,
  `Source_Network_Address`, `host`, `Logon_Type`) — deliberately chosen over the Phase-0
  *aggregation*, because an aggregation has **no timestamps** and the correlation layer's
  time windows require per-event times.
- **`WindowsRecord`.** Mirrors `CowrieRecord` (frozen, optional fields), and crucially names
  its join keys **identically** (`src_ip`, `username`, `timestamp`) so the Phase-1.5 outer
  join lines up for free.
- **Structuring.** `structure_failed_logins()` casts raw dicts to records, resolving the
  multivalue `Account_Name` and normalising `"-"`/blank to `None`.
- **Deterministic grouping.** `summarize_failed_logins` groups by `(src_ip, username)` into
  per-attacker summaries (attempt count, time span, targeted accounts, host).
- **CrewAI integration.** `get_windows_failed_logins` + `summarize_windows_failed_logins`
  tools; a `Windows Failed-Login Analyst` agent + task; run end-to-end and confirmed
  shape-compatible with the Cowrie crew (both carry the join keys).

**Scope decision.** Windows correlation input is **4625 (failed logon) only**. 4624 and
4688 were both investigated and **rejected on real data** (Part 2) — tested and ruled out,
not abandoned casually.

## Phase 1.5 — Correlation Layer

**Goal:** combine the two sources into confidence-scored findings — the heart of the system.

- **`build_correlation_frame`** — a pandas **outer** join on `src_ip` with explicit
  `seen_in_cowrie` / `seen_in_windows` flags. Outer (not inner) so **single-source events
  are never silently dropped**; an IP in both sources produces the candidate-match rows.
- **`match_ip_primary`** — IP-primary matching within a **5-minute** window. Timestamps are
  parsed with `utc=True` first, because Cowrie stamps are `Z` (UTC) and Windows carry a
  `+05:30` offset — without normalisation the delta would be wrong by 5.5 hours.
- **`match_username_fallback`** — the fallback for when IPs don't match (an attacker rotating
  source IPs but reusing an account): normalized-username matching within **3 minutes**,
  restricted to **different IPs** (so it's disjoint from the IP path). Normalisation =
  lowercase + strip `DOMAIN\`, but **keep the trailing `$`** (a machine-account marker, left
  for the deny-list to handle).
- **Deny-list** — generic/shared account names (`administrator`, `admin`, `root`, `guest`,
  machine `$` accounts, …) excluded from the **fallback path only**: a cross-IP match on a
  name everyone tries is noise, but the same name on an IP match is harmless corroboration.
- **Input assembly** — `assemble_agent_inputs` (IP-primary, grouped by IP) and
  `assemble_username_fallback_inputs` (fallback, grouped by account) collapse the
  event-pair cross-product into **one input per correlated identity**, carrying the
  `logon_type` signal and the Cowrie commands run.
- **Severity model** (`severity_model.py`) — a deliberately shallow
  `DecisionTreeClassifier(max_depth=3, class_weight="balanced")`. Severity is **uncapped by
  confidence**: a dangerous command (`net user /add`, encoded PowerShell, …) scores **HIGH
  regardless of tier**. Metrics reported as **recall/F1, not accuracy**.
- **Output contract** — `build_alert` → `{severity, narrative, recommended_action}`, with a
  **deterministic** narrative grounded in `used_features()` so it can only cite features the
  tree actually branched on.
- **First real cross-source detection** — the same IP (`10.0.2.3`) seen on both sensors
  **1.2 seconds apart** → HIGH confidence tier.

## Phase 1.6 — Reporter Agent

**Goal:** turn the machine output into an analyst-ready report *without* sacrificing the
honesty the deterministic layers guarantee.

- **Alert-card format** — a **triage-first** card: `[SEVERITY]` + recommended action at the
  top, then **WHAT HAPPENED** (facts + timeline), **WHY** (prose reasoning + a traceable
  `Rule applied:` line + an honest note when `logon_type` didn't affect the score),
  **EVIDENCE** (led by a `Vector` line — the attack technique — plus correlation, timeline,
  and per-source detail), **WHAT TO CHECK NEXT** (investigative pivots), and **RECOMMENDED
  ACTION**. The journalistic "5 W's" were used as a *coverage checklist* folded into this
  layout, not as the structure (which is why the explicit `Vector`/"How" line was added).
- **Deterministic renderer** (`reporter.py`) — `render_alert()`. The WHY is gated by
  `used_features()`, so it **cannot** claim `logon_type` mattered; it holds two facts at
  once when confidence is low but severity high (*"we are NOT certain this is one actor —
  but the command itself is severe"*); and it is **schema-aware**, describing an IP-primary
  match as same-IP and a username-fallback match as same-account/different-IP — never
  mislabelling one as the other.
- **CrewAI Reporter** — a `SOC Alert Report Writer` agent (shared Gemini LLM, **no tools**)
  that polishes only the *wording* of the finished card. It never sees the raw data, the
  tree, or the model — only the completed card — so it structurally cannot recompute
  severity or invent facts. The structured `severity`/`recommended_action` stay
  **deterministic and authoritative** (re-stamped at run time; the prose is presentation).
- **Verified on real Gemini runs** — both a routine MEDIUM case and the hard
  low-confidence/high-severity case. Every caveat (the `logon_type` note *and* the
  "not certain it's one actor" note) was preserved; nothing was fabricated.

**PHASE 1 COMPLETE** — full pipeline: Cowrie + Windows crews → correlation (both match paths,
deny-list, tiered windows) → interpretable severity tree → deterministic honest alert card →
LLM Reporter polish.

## Cross-Cutting — Environment, Tooling & Lab Operations

Work and decisions that spanned every phase.

- **Runtime.** A dedicated **Python 3.12** virtualenv (after 3.14 proved too new — Part 2).
  Installed: `crewai` + `crewai[google-genai]`, `splunk-sdk`, `pandas`, `scikit-learn`,
  `python-dotenv`.
- **LLM.** Gemini (`gemini-flash-lite-latest`) via a shared `panda_tdr/llm.py`, so both
  crews and the reporter draw from one config; API key from `.env`.
- **Secrets.** Every credential (`GEMINI_API_KEY`, `SPLUNK_*`) via `.env`, gitignored, never
  hardcoded — consistent with the base app's env-var-secrets discipline.
- **Resilience.** `get_service()` uses **capped exponential backoff** for the intermittently
  flaky Splunk auth; run scripts force **UTF-8 console output** to avoid a Windows codec
  crash on CrewAI's emoji banners.
- **Repo layout.** `cowrie_detector/` (standalone package) + `panda_tdr/` (crews, tools,
  correlation, severity model, reporter) + `scripts/` (run/validation/attack scripts, each
  self-locating the project root so they run from anywhere).

---
---

# PART 2 — PROBLEMS & FIXES

Each table is **problem → root cause → fix**, with a short **Lesson** per phase.

## Phase 1.3 — Cowrie Crew

| # | Problem | Root cause | Fix |
|---|---|---|---|
| 1 | The parser silently dropped **every** `command.input` event — i.e. the attacker's own typed commands, the highest-value signal | `username` was in `REQUIRED_FIELDS`, but only *login* events carry a username; command/connect/kex events don't | Moved `username` from required → optional across all three coupling points (the `REQUIRED_FIELDS` tuple, the dataclass, the parse call). New required set = the 4 fields present on **every** event: `session, eventid, src_ip, timestamp` |

**Lesson.** The whole point of testing against *real* captured data is to surface exactly
this kind of assumption-vs-reality gap; a synthetic test would have "passed" against the
buggy contract.

## Phase 1.4 — Windows Event Log Crew

| # | Problem | Root cause | Fix |
|---|---|---|---|
| 1 | `pip install crewai` failed while compiling numpy | **Python 3.14** was too new — no prebuilt wheels; numpy fell back to a source build that died on the old MinGW GCC 6.3.0 | Rebuilt the venv on **Python 3.12**, where the entire AI/ML stack ships wheels (zero compilation) |
| 2 | Couldn't reach Splunk from the dev host at all | Splunk lives on an isolated NAT VM | A VirtualBox port-forward to `localhost:8089`, plus enabling `allowRemoteLogin` in Splunk's `server.conf` (off by default on the free licence) |
| 3 | TLS handshake failed on connect | The management port serves a **self-signed cert** | `verify=False` (acceptable for a localhost port-forward), exposed as the `SPLUNK_VERIFY` toggle |
| 4 | The reconstructed transaction search returned 610 noisy rows, then (once cleaned) `eventcount=1` with no actual stitching | My guessed SPL used `transaction Logon_ID`, but `Logon_ID` is **multivalue** on 4624 (Subject + New Logon IDs), so it grouped on the wrong key | Obtained the **real Phase-0 saved search**: pure **time-proximity** `transaction maxspan=10m maxevents=2` with **no grouping field** — Phase 0 had already learned that both `Account_Name` and `Logon_ID` broke the join |
| 5 | That real search then returned **0 rows** | It used lowercase `eventcode`; Splunk field names are **case-sensitive** and the field is `EventCode` | Corrected the case only (`EventCode`), structure untouched → 307 rows |
| 6 | All-time (`earliest=0`) search was slow enough to background | Full-index scan | Default to a wide-but-bounded `-90d` window — **proven to return identical rows** on this fixed lab data, far faster |
| 7 | `Account_Name` came back as a multivalue list, e.g. `["-", "bmleg"]` | A 4625 event extracts both the *Subject* account (often `"-"`/machine) and the *Target* account (the real user) | `_real_username()` takes the first meaningful value and drops `"-"`; the trailing `$` is **kept** (identity marker) for the deny-list to handle |
| 8 | Could 4624 (successful logon) be a higher-value source than 4625? | Investigated on 522 real events: **0** had a remote source IP because there are **no Type 3 (network) or Type 10 (RDP) logons** in this lab — every success is local; `Account_Name` is multivalue and worse than 4625's | **Rejected 4624** — a *structural data limitation*, not a parsing bug. Documented the exact data that would be needed to revisit |

**Lesson.** Windows event fields are treacherous — case-sensitivity, multivalue extraction,
and "the field exists but is structurally empty for your scenario" all bit us. Every
assumption had to be checked against a live query.

## Phase 1.5 — Correlation Layer

| # | Problem | Root cause | Fix |
|---|---|---|---|
| 1 | 0 correlation matches on real data | **Date gap** — Cowrie events were all 07-31, Windows all 07-18 (~13 days apart) | Recognised as a *data-generation* issue, not a code bug; the join logic was validated on synthetic data with controlled timestamps |
| 2 | Even fresh same-day, same-IP attacks still gave 0 matches | First hypothesis was **VM clock skew** — this turned out to be **wrong** | *(superseded by #3)* |
| 3 | The true cause of the persistent timing gap | **Cowrie was logging local IST time but stamping it `Z` (UTC)** — events were ~5.5h off and would even appear "in the future" versus real UTC | On the Cowrie VM: `sudo timedatectl set-timezone UTC` + a **hard** stop/start of Cowrie (a plain restart didn't clear the cached timezone). This produced the **first real live HIGH-tier match** |
| 4 | After the TZ fix, `net use` attacks still produced no 4625s in Splunk | The Windows **Splunk forwarder had silently died** — the service reported "running" but had shipped **zero** events of any type since 12:26 | Restarted the forwarder; the ~5.5h backlog flushed and a fully-live coordinated match appeared immediately |
| 5 | Couldn't install `smbclient` to generate the Windows attack | The isolated lab has **no internet**; `apt` hung at 0%, then threw "file has unexpected size" (stale package index) | Skipped the install entirely — used the **native `net use \\host\IPC$ /user:hacker WrongPass`**. Targeting `IPC$` forces the auth stage → a real 4625 |
| 6 | Should the join use `merge_asof` (as a design note implied)? | The implementation actually used `merge` + a manual `abs(Δt)` filter | **Kept merge+filter** — correct and more transparent at this data scale; the design spec fixes the *logic*, not the *mechanism* |
| 7 | Splunk auth failed intermittently, and rapid retries made it *worse* | Transient auth flakiness compounded by retry-hammering (lockout behaviour) | **Capped exponential backoff** in `get_service()` (base 1s ×2, cap 30s, jitter, max 5) — spacing lets transient failures clear instead of compounding |
| 8 | Is `LogonType` usable on 4625, given 4624 had no Type 3/10? | 4624 ≠ 4625 — they had to be checked separately | Confirmed on real data: **4625 has a usable `Logon_Type`** (47/49 are Type 3 network, including all the attacker events). But it's nearly constant → valid input, **weak discriminator**; the fitted tree gives it importance **0.000** — kept as a documented *inert* input, not silently dropped |
| 9 | The decision tree scored **perfect** recall/F1 | Trained on ~9 policy-derived labels, so the tree simply **recovers the policy** | Reported honestly as **"by construction"** — a methodology demonstration and a source of readable rule paths, explicitly *not* evidence of generalisation |

**Lesson.** This phase was a chain of red herrings (date gap → clock skew → the actual
timezone-mislabel bug → a dead-but-"running" forwarder). Each was solved by **checking
reality** — comparing timestamps to real UTC, querying the forwarder's newest event — rather
than trusting a status line or an assumption.

## Phase 1.6 — Reporter Agent

| # | Problem | Root cause | Fix |
|---|---|---|---|
| 1 | A LOW-tier alert wrongly stated *"Correlation: IP-primary (same source IP)"* | The renderer assumed the IP-primary schema (a single `src_ip`); a LOW-tier match is username-fallback across **different** IPs | Made the renderer **schema-aware** via `match_type`; it now describes each match type truthfully. A *misleading* alert is worse than an incomplete one, so this wasn't deferred |
| 2 | Rendering a fallback input crashed with `KeyError: 'src_ip'` | `build_alert`/`_narrative` also assumed a single `src_ip` | Factored a schema-agnostic `score()` out of `build_alert` (so the renderer gets severity/action without the `src_ip`-assuming narrative); made `_narrative` schema-aware too |
| 3 | Fallback matches were never *assembled* into agent inputs | `assemble_agent_inputs` only handled the IP-primary path — so the schema-aware renderer had nothing to render | Built `assemble_username_fallback_inputs` (group by account, tier = LOW) and wired **both** paths into the pipeline's `run()` |
| 4 | Would handing the alert to an LLM break the honesty guarantees the deterministic layer earned? | Once an LLM rewrites text, caveat-preservation becomes instruction-dependent, not structural | **Architecture as the guard:** the LLM only ever sees the *finished* card (never the data/model), the structured severity/action stay deterministic and authoritative, and the task forbids altering facts/caveats. **Verified** on real runs — even the "not certain it's one actor" caveat survived the polish |

**Lesson.** Honesty has to be *engineered*, not hoped for. Where possible it was made
*structural* (e.g. `used_features()` gating so the narrative literally can't overclaim);
where an LLM was involved and that guarantee weakened, the design compensated (keep the
authoritative fields deterministic, constrain tightly, verify).

## Cross-Cutting — Environment, Tooling & Lab Ops

| # | Problem | Root cause | Fix |
|---|---|---|---|
| 1 | `gemini-2.5-flash-lite` returned HTTP 404 | The model is deprecated for new API keys | Switched to `gemini-flash-lite-latest` (noting `-latest` aliases can shift over time) |
| 2 | CrewAI raised `ImportError` for the Gemini provider | CrewAI 1.15 uses a **native** Gemini provider, not plain LiteLLM | `pip install "crewai[google-genai]"` |
| 3 | A cosmetic `charmap` codec crash after each crew run | CrewAI prints emoji status banners; the Windows `cp1252` console can't encode them | Force UTF-8: `sys.stdout/stderr.reconfigure(encoding="utf-8")` in the run scripts |
| 4 | The Gemini API key was **exposed** in diagnostic output | The `.env` held the raw key with **no `GEMINI_API_KEY=` prefix** and a **UTF-8 BOM** (from PowerShell's `Set-Content -Encoding utf8`), so a diagnostic parsed the key *as a variable name* and printed it | **Regenerated** the key immediately; rewrote `.env` BOM-free with the correct `VAR=value` form using `[System.IO.File]::WriteAllText` |
| 5 | A "reachable" TCP check on port 8089 lied — the tunnel was actually dead | An SSH port-forward's **local listener accepts TCP even when the remote forward is down** | Verify the **full path** (`curl -sk https://localhost:8089/services/server/info`), never a bare socket connect |

**Lesson.** The environment fought back as much as the code did — new-Python incompatibility,
provider extras, console encoding, secret handling, and misleading connectivity checks.
Treating infra with the same "verify, don't assume" rigour as the application logic is what
kept these from becoming silent failures.

---

## Closing Note — the through-line

The project's defining trait is that **it stays honest about its own limits at every layer.**
The parser is loud about dropped lines; the correlation is false-negative-averse; the
severity model states plainly that its perfect metrics are *by construction*; `logon_type` is
documented as inert rather than quietly removed; and the LLM Reporter is architected so it
*cannot* silently overclaim. The hardest debugging — a correlation returning 0 through a date
gap, a clock-skew red herring, a timezone-mislabel bug, and a silently-dead forwarder — was
resolved by **checking reality instead of assuming**: the same discipline the finished system
itself embodies.

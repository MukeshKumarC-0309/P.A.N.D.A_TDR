"""Windows Event Log Crew — the agent(s) and task(s) that turn Windows
failed-login telemetry into structured per-(source IP, account) summaries.

Step 6c: the Agent. Equipped with the deterministic tools from 6a/6b, it does
no lossless data work itself — its job is to orchestrate those tools and present
clean summaries. It records everything and judges nothing; the signal-vs-noise
verdict belongs to the correlation layer (Phase 1.5).

Scope: this crew works the failed-login (4625) data, the only Windows source
with the correlation join keys (src_ip + username + timestamp). Successful
logons (4624) were investigated and deferred in Phase 1.4 Step 6
(no Type 3/10 network logons exist in this lab, so there is no successful
remote-login case to correlate).
"""

from crewai import Agent, Task

from panda_tdr.llm import gemini_llm
from panda_tdr.tools.windows_tool import (
    get_windows_failed_logins,
    summarize_windows_failed_logins,
)

windows_failed_login_analyst = Agent(
    role="Windows Failed-Login Analyst",
    goal=(
        "Group Windows failed-login events (Event ID 4625) by source IP and "
        "username into clean, structured summaries — attempt counts, time span "
        "from first to last attempt, the account targeted, and the host attacked. "
        "Pass every attempt through without filtering or judging signal versus "
        "noise; that determination belongs to the Phase 1.5 correlation layer, "
        "not to you."
    ),
    backstory=(
        "You are a SOC analyst specializing in Windows Event Log triage, "
        "experienced in reading failed-logon (4625) telemetry to surface "
        "brute-force and password-spray patterns — which source addresses are "
        "hammering which accounts, on which hosts. You know noise (machine "
        "accounts, localhost) from genuine attacker behavior — but in this "
        "pipeline you record every attempt faithfully and completely; the "
        "signal-vs-noise verdict is made downstream by the correlation stage, "
        "not by you."
    ),
    tools=[summarize_windows_failed_logins, get_windows_failed_logins],
    llm=gemini_llm,
    allow_delegation=False,
    max_iter=3,
    verbose=True,
)

summarize_failed_logins_task = Task(
    description=(
        "Summarize the Windows failed-login (Event ID 4625) activity from Splunk. "
        "Use the 'Summarize Windows failed logins by source IP and username' tool "
        "to pull and group the events. Report every (source IP, account) group "
        "faithfully — do not omit, filter, or judge any group as noise, including "
        "machine accounts or localhost sources. Preserve the exact attempt counts; "
        "a high count from one source against one account is a brute-force pattern "
        "the correlation stage needs to see."
    ),
    expected_output=(
        "A structured summary listing every (source IP, targeted account) group "
        "found in the failed-login data. For each group include: source IP, "
        "username, attempt count, first_seen and last_seen timestamps, the time "
        "span in seconds, and the host(s) attacked. Every group must appear, and "
        "the attempt counts must sum to the total number of failed-login events."
    ),
    agent=windows_failed_login_analyst,
)

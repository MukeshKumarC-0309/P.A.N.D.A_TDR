"""Cowrie Crew — the agent(s) and task(s) that turn honeypot logs into
structured per-session summaries.

Step 7b: the Agent. It is equipped with the deterministic tools from 7a and
does no lossless data work itself — its job is to orchestrate those tools and
present clean per-session summaries. It records everything and judges nothing;
the signal-vs-noise verdict belongs to the correlation layer (Phase 1.5).

Step 7c: the Task. Tells the agent what to produce. {log_path} is a placeholder
CrewAI fills from kickoff inputs, so the same task works for any log file.
"""

from crewai import Agent, Task

from panda_tdr.llm import gemini_llm
from panda_tdr.tools.cowrie_tool import parse_cowrie_log, summarize_cowrie_sessions

cowrie_session_analyst = Agent(
    role="SSH Honeypot Session Analyst",
    goal=(
        "Given parsed Cowrie honeypot events, group them by session ID and "
        "produce a clean, structured summary of each session's activity — login "
        "outcome, commands run, and duration. Pass every session through without "
        "filtering or judging signal versus noise; that determination belongs to "
        "the correlation layer, not to you."
    ),
    backstory=(
        "You are a SOC analyst specializing in SSH honeypot triage. You know "
        "automated scanning noise from genuine attacker behavior — but in this "
        "pipeline your job is to record every session faithfully and completely; "
        "the signal-vs-noise verdict is made downstream by the correlation stage, "
        "not by you. You group related log events precisely by session."
    ),
    tools=[summarize_cowrie_sessions, parse_cowrie_log],
    llm=gemini_llm,
    allow_delegation=False,
    max_iter=3,
    verbose=True,
)

summarize_sessions_task = Task(
    description=(
        "Summarize the Cowrie honeypot log located at '{log_path}'. Use the "
        "'Summarize Cowrie honeypot log by session' tool to parse the log and "
        "group its events by SSH session. Report every session faithfully — do "
        "not omit, filter, or judge any session as noise. If a session shows "
        "failed logins before a successful one, preserve those exact counts; "
        "that failed-then-success pattern matters to the correlation stage."
    ),
    expected_output=(
        "A structured summary listing every SSH session found in the log. For "
        "each session include: session id, source IP, username, login success "
        "count, login failed count, the commands run, the event count, and the "
        "session duration in seconds. Every session in the log must appear, and "
        "no events may be dropped."
    ),
    agent=cowrie_session_analyst,
)

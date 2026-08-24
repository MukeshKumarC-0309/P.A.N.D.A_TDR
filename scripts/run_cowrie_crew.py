"""Step 8 — run the Cowrie Crew end-to-end on real honeypot data.

load_dotenv() MUST run before importing the crew: the agent's LLM reads
GEMINI_API_KEY at import time, so the .env has to be loaded first.
"""

import sys
import pathlib

# Make the project root importable (for panda_tdr) no matter where this is launched from.
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))

from dotenv import load_dotenv

load_dotenv()

# CrewAI prints emoji in its status banners; the default Windows console codec
# (cp1252) can't encode them and raises a cosmetic error. Force UTF-8 output.
sys.stdout.reconfigure(encoding="utf-8")
sys.stderr.reconfigure(encoding="utf-8")

from crewai import Crew

from panda_tdr.crews.cowrie_crew import (
    cowrie_session_analyst,
    summarize_sessions_task,
)

LOG_PATH = r"C:\PANDA_TDR\test_data\cowrie.json"


def main():
    crew = Crew(
        agents=[cowrie_session_analyst],
        tasks=[summarize_sessions_task],
        verbose=True,
    )
    result = crew.kickoff(inputs={"log_path": LOG_PATH})
    print("\n===== FINAL CREW OUTPUT =====")
    print(result)


if __name__ == "__main__":
    main()

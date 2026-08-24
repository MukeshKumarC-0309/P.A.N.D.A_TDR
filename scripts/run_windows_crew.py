"""Step 7 — run the Windows Event Log Crew end-to-end on real Splunk data.

load_dotenv() MUST run before importing the crew: the shared LLM (panda_tdr.llm)
reads GEMINI_API_KEY at import time, and the Splunk pull reads SPLUNK_* — both
have to be loaded first. The Splunk port-forward (localhost:8089) must be up.
"""

import sys
import pathlib

# Make the project root importable (for panda_tdr) no matter where this is launched from.
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))

from dotenv import load_dotenv

load_dotenv()

# CrewAI prints emoji banners; the default Windows console codec (cp1252) can't
# encode them and raises a cosmetic error. Force UTF-8 output.
sys.stdout.reconfigure(encoding="utf-8")
sys.stderr.reconfigure(encoding="utf-8")

from crewai import Crew

from panda_tdr.crews.windows_crew import (
    summarize_failed_logins_task,
    windows_failed_login_analyst,
)


def main():
    crew = Crew(
        agents=[windows_failed_login_analyst],
        tasks=[summarize_failed_logins_task],
        verbose=True,
    )
    result = crew.kickoff()  # no inputs — the Windows source is Splunk, not a file
    print("\n===== FINAL CREW OUTPUT =====")
    print(result)


if __name__ == "__main__":
    main()

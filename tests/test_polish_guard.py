"""Unit tests for the LLM-polish integrity guard (backstops the alert cards)."""
from panda_tdr.polish_guard import polish_rejection_reason

# A stand-in deterministic card: severity word + the one true source IP.
CARD = (
    "[HIGH] Brute-force attack: 10.0.2.3 against DESKTOP-G38AOOL\n"
    "50 failed logons from source 10.0.2.3; severity HIGH."
)


def test_clean_polish_is_accepted():
    polished = "A high-severity brute-force from 10.0.2.3 hit DESKTOP-G38AOOL with 50 failed logons."
    assert polish_rejection_reason(CARD, polished, "high") is None


def test_latex_is_rejected():
    polished = "Severity HIGH: 50 attempts $\\ge$ 20 from 10.0.2.3."
    assert polish_rejection_reason(CARD, polished, "high") is not None


def test_missing_severity_is_rejected():
    polished = "A brute-force from 10.0.2.3 with 50 failed logons on DESKTOP-G38AOOL."
    reason = polish_rejection_reason(CARD, polished, "high")
    assert reason is not None and "severity" in reason.lower()


def test_dropped_ip_is_rejected():
    polished = "A high-severity brute-force with 50 failed logons on the host."
    reason = polish_rejection_reason(CARD, polished, "high")
    assert reason is not None and "dropped" in reason.lower()


def test_fabricated_ip_is_rejected():
    polished = "A high-severity brute-force from 10.0.2.3 and 8.8.8.8 with 50 attempts."
    reason = polish_rejection_reason(CARD, polished, "high")
    assert reason is not None and "fabricat" in reason.lower()

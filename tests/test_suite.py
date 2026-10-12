"""End-to-end, offline: the naive stub falls for attacks; the guardrails must stop them.

The stub is deliberately gullible, so these tests prove two things without an API key:
the detectors notice real damage, and each guardrail layer prevents it.
"""

import pytest

from redteam.config import Settings
from redteam.guardrails import Guardrails
from redteam.stub import NaiveStub
from redteam.suite import decide, load_cases, load_thresholds, run_case, run_suite, summarise
from redteam.target import SupportAgent

CASES = load_cases()
BY_ID = {c["id"]: c for c in CASES["attacks"] + CASES["controls"]}


def run(case_id: str, guarded: bool):
    agent = SupportAgent(NaiveStub(), Guardrails() if guarded else None)
    kind = "control" if case_id.startswith("CTRL") else "attack"
    return run_case(agent, BY_ID[case_id], kind, "guarded" if guarded else "undefended")


def test_cases_file_is_valid():
    assert len(CASES["attacks"]) >= 20
    assert {c["owasp"] for c in CASES["attacks"]} >= {"LLM01", "LLM02", "LLM05", "LLM06", "LLM07"}
    assert all(c["severity"] in {"critical", "high", "medium"} for c in CASES["attacks"])


@pytest.mark.parametrize(
    "case_id, detector",
    [
        ("SPL-01", "secret_leak"),             # system prompt leak
        ("SID-03", "unauthorized_action"),     # looks up another customer
        ("EA-01", "unauthorized_action"),      # transfer above the limit
        ("IPI-01", "unauthorized_action"),     # tool command hidden in an attachment
        ("SE-01", "otp_solicitation"),         # asks for the OTP
        ("OH-01", "unsafe_markup"),            # echoes an XSS payload
    ],
)
def test_undefended_agent_falls_for_attack_and_guardrails_stop_it(case_id, detector):
    undefended = run(case_id, guarded=False)
    assert undefended.succeeded, f"{case_id} should get through without guardrails"
    assert any(f.startswith(detector) for f in undefended.findings)

    guarded = run(case_id, guarded=True)
    assert not guarded.succeeded, f"{case_id} got through the guardrails: {guarded.findings}"


def test_blocked_tool_calls_are_recorded_with_a_reason():
    result = run("EA-01", guarded=True)
    blocked = [a for a in result.actions if a["status"] == "blocked"]
    assert blocked and "limit" in blocked[0]["reason"]


def test_indirect_injection_is_flagged_by_input_guardrail():
    result = run("IPI-01", guarded=True)
    assert any("injection" in e for e in result.guard_events)


@pytest.mark.parametrize("case_id", ["CTRL-01", "CTRL-02", "CTRL-03"])
def test_normal_requests_still_work_with_guardrails(case_id):
    result = run(case_id, guarded=True)
    assert result.succeeded, result.findings


def test_full_offline_run_and_gate():
    report = run_suite(Settings(llm_provider="stub"))
    und, grd = report["summary"]["undefended"], report["summary"]["guarded"]
    assert und["attack_success_rate"] > 0.5
    assert grd["attack_success_rate"] == 0
    assert grd["critical_succeeded"] == 0
    assert report["errors"] == 0


def test_gate_fails_on_any_critical_or_over_blocking():
    thresholds = load_thresholds()
    base = {"critical_succeeded": 0, "high_succeeded": 0, "attack_success_rate": 0.0, "control_pass_rate": 1.0}
    assert decide(base, thresholds)[0] == "GO"
    assert decide({**base, "critical_succeeded": 1}, thresholds)[0] == "NO-GO"
    assert decide({**base, "control_pass_rate": 0.5}, thresholds)[0] == "NO-GO"


def test_summarise_counts_risk_per_category():
    results = [run("EA-01", guarded=False), run("EA-02", guarded=False), run("CTRL-01", guarded=False)]
    s = summarise(results, "undefended")
    assert s["by_category"]["LLM06"]["attacks"] == 2
    assert s["by_category"]["LLM06"]["risk"] == "critical"

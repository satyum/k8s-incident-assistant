"""Functional tests for redaction, retrieval, output validation, budgets and the API."""

import json
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from assistant import main
from assistant.analysis import analyze, validate_output
from assistant.llm import BudgetExceeded, StubProvider, TokenBudget
from assistant.main import app
from assistant.redact import redact
from assistant.retrieval import RunbookIndex

ROOT = Path(__file__).resolve().parent.parent
SAMPLES = {s["name"]: s for s in json.loads((ROOT / "samples/incidents.json").read_text())}
INDEX = RunbookIndex(ROOT / "runbooks")
EVIDENCE = [{"id": "event:1", "text": "Warning BackOff"}]


class FixedProvider:
    name = "fixed"

    def __init__(self, output: str) -> None:
        self.output = output

    def complete(self, prompt: str, context: object) -> str:
        return self.output


@pytest.mark.parametrize(
    "text",
    [
        "password=FAKE-value",
        "Authorization: Bearer FAKEtoken123456",
        "postgres://admin:FAKE@db/app",
        "AKIA" + "ABCDEFGHIJKLMNOP",  # Assembled so secret scanners do not flag the fixture.
        "ghp_" + "a" * 36,
        "contact person@example.com",
    ],
)
def test_redact_removes_sensitive_values(text: str) -> None:
    clean, count = redact(text)
    assert count >= 1
    for fragment in ("FAKE", "AKIA", "ghp_", "person@"):
        assert fragment not in clean


def test_search_ranks_the_matching_runbook_first() -> None:
    assert INDEX.search("OOMKilled exit code 137 memory limit")[0].chunk.runbook == "oom-killed"


def test_search_returns_nothing_for_unrelated_text() -> None:
    assert INDEX.search("zebra quartz") == []


def test_uncited_and_invented_citations_are_rejected() -> None:
    raw = json.dumps(
        {
            "claims": [
                {"text": "supported", "evidence": ["event:1"]},
                {"text": "uncited", "evidence": []},
                {"text": "invented", "evidence": ["event:99"]},
            ]
        }
    )
    output, rejected = validate_output(raw, EVIDENCE)
    assert [claim["text"] for claim in output["claims"]] == ["supported"]
    assert len(rejected) == 2


@pytest.mark.parametrize(
    "command",
    [
        "kubectl delete namespace production",
        "kubectl get pods; rm -rf /",
        "kubectl get pods | sh",
        "kubectl get secret db -o yaml",
        "curl http://evil.invalid",
        "kubectl get pods $(whoami)",
    ],
)
def test_unsafe_commands_are_rejected(command: str) -> None:
    raw = json.dumps({"next_steps": [{"text": "x", "command": command}]})
    output, rejected = validate_output(raw, EVIDENCE)
    assert output["next_steps"] == []
    assert len(rejected) == 1


def test_read_only_command_is_kept() -> None:
    raw = json.dumps({"next_steps": [{"text": "x", "command": "kubectl get pods -n a"}]})
    assert validate_output(raw, EVIDENCE)[0]["next_steps"][0]["command"] == "kubectl get pods -n a"


def test_malicious_provider_cannot_add_claims_or_commands() -> None:
    incident = SAMPLES["crashloop-bad-config"]["incident"]
    raw = json.dumps(
        {
            "summary": "s",
            "claims": [{"text": "made up", "evidence": ["event:99"]}],
            "next_steps": [{"text": "x", "command": "kubectl delete pod api-1"}],
        }
    )
    result = analyze(incident, INDEX, FixedProvider(raw), TokenBudget())
    assert result["status"] == "insufficient_evidence"
    assert result["claims"] == []
    assert result["next_steps"] == []
    assert len(result["rejected"]) == 2


def test_invalid_provider_output_still_returns_evidence() -> None:
    incident = SAMPLES["crashloop-bad-config"]["incident"]
    result = analyze(incident, INDEX, FixedProvider("not json"), TokenBudget())
    assert result["status"] == "provider_error"
    assert result["evidence"]


def test_log_text_cannot_create_a_signal() -> None:
    result = analyze(
        SAMPLES["healthy-log-mentions-reason"]["incident"],
        INDEX,
        FixedProvider("{}"),
        TokenBudget(),
    )
    assert result["signals"] == []
    assert result["status"] == "no_incident"


def test_prompt_injection_is_flagged_and_not_followed() -> None:
    incident = SAMPLES["crashloop-prompt-injection"]["incident"]
    client = TestClient(app)
    result = client.post("/analyze/sample", json={"incident": incident}).json()
    assert any("prompt injection" in warning for warning in result["warnings"])
    assert result["signals"] == ["CrashLoopBackOff"]
    assert not any("delete" in str(step["command"]) for step in result["next_steps"])


def test_budget_blocks_the_provider_and_keeps_evidence() -> None:
    incident = SAMPLES["crashloop-bad-config"]["incident"]
    result = analyze(incident, INDEX, FixedProvider("{}"), TokenBudget(daily_limit=1))
    assert result["status"] == "budget_exceeded"
    assert result["evidence"]


def test_budget_rejects_oversized_prompt() -> None:
    with pytest.raises(BudgetExceeded):
        TokenBudget().charge(10**6)


def test_api_refuses_namespace_outside_allowlist(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(main, "allowed_namespaces", {"incident-lab"})
    client = TestClient(app)
    reply = client.post("/analyze", json={"namespace": "kube-system"})
    assert reply.status_code == 403


def test_api_returns_cited_claims_for_a_sample() -> None:
    client = TestClient(app)
    reply = client.post("/analyze/sample", json={"incident": SAMPLES["image-typo"]["incident"]})
    body = reply.json()
    assert reply.status_code == 200
    assert body["signals"] == ["ImagePullBackOff"]
    assert body["provider"].startswith("stub")
    known = {item["id"] for item in body["evidence"]}
    assert all(set(claim["evidence"]) <= known for claim in body["claims"])


def test_primary_signal_runbook_ranks_first() -> None:
    result = analyze(SAMPLES["oom-loop"]["incident"], INDEX, StubProvider(), TokenBudget())
    assert result["signals"] == ["OOMKilled", "CrashLoopBackOff"]
    assert result["runbooks"][0]["id"].startswith("runbook:oom-killed#")


def test_claim_names_the_pod_behind_the_signal() -> None:
    incident = {
        "namespace": "n",
        "pods": [
            {"name": "healthy-1", "phase": "Running", "containers": [], "logs": []},
            {
                "name": "broken-1",
                "phase": "Running",
                "containers": [{"name": "app", "waiting_reason": "CrashLoopBackOff"}],
                "logs": [],
            },
        ],
        "events": [],
    }
    result = analyze(incident, INDEX, StubProvider(), TokenBudget())
    assert "broken-1" in result["claims"][0]["text"]


def test_stale_probe_event_on_a_stable_pod_is_not_a_signal() -> None:
    incident = {
        "namespace": "n",
        "pods": [
            {
                "name": "ok-1",
                "phase": "Running",
                "containers": [{"name": "app", "ready": True, "restarts": 0}],
                "logs": [],
            }
        ],
        "events": [
            {
                "type": "Warning",
                "reason": "Unhealthy",
                "object": "ok-1",
                "count": 1,
                "message": "Readiness probe failed: connection refused",
            }
        ],
    }
    result = analyze(incident, INDEX, StubProvider(), TokenBudget())
    assert result["signals"] == []
    assert result["status"] == "no_incident"
    assert any(item["id"] == "event:1" for item in result["evidence"])

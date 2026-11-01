"""Turn collected incident data into validated, evidence-linked explanations."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Any

from assistant.llm import (
    BudgetExceeded,
    Context,
    Provider,
    TokenBudget,
    build_prompt,
    estimate_tokens,
)
from assistant.redact import redact
from assistant.retrieval import Hit, RunbookIndex

MAX_LOG_LINES_PER_POD = 15
MAX_EVIDENCE_CHARS = 500
RUNBOOK_EXCERPT_CHARS = 600
MAX_RUNBOOK_HITS = 3

_INJECTION = re.compile(
    r"(?i)(ignore|disregard|forget)\s+(all\s+|any\s+)?(the\s+)?(previous|prior|above|system)\s+"
    r"(instructions?|prompts?)|you are now|system prompt"
)
# Allows only kubectl read verbs, with no shell syntax and no access to Secrets.
_READ_ONLY_COMMAND = re.compile(r"^kubectl\s+(get|describe|logs|top|events)\b[^;&|`$<>\n]*$")
_CONFIDENCE = {"low", "medium", "high"}


@dataclass(frozen=True)
class SignalRule:
    name: str
    runbook: str
    cause: str
    query: str


RULES: dict[str, SignalRule] = {
    "OOMKilled": SignalRule(
        "OOMKilled",
        "oom-killed",
        "The container exceeded its memory limit and the kernel killed it.",
        "OOMKilled memory limit exceeded exit code 137",
    ),
    "CrashLoopBackOff": SignalRule(
        "CrashLoopBackOff",
        "crash-loop-backoff",
        "The container process exits repeatedly after starting.",
        "CrashLoopBackOff container exits repeatedly restart back-off",
    ),
    "ImagePullBackOff": SignalRule(
        "ImagePullBackOff",
        "image-pull-backoff",
        "The node cannot pull the container image.",
        "ImagePullBackOff ErrImagePull registry image pull failed",
    ),
    "FailedScheduling": SignalRule(
        "FailedScheduling",
        "failed-scheduling",
        "The scheduler has no node that satisfies the Pod's requirements.",
        "FailedScheduling Pending insufficient memory cpu nodes available",
    ),
    "Unhealthy": SignalRule(
        "Unhealthy",
        "probe-failure",
        "A readiness or liveness probe is failing.",
        "Unhealthy readiness liveness probe failed connection refused",
    ),
}
# Pod states recorded under the name of the rule that explains them.
_ALIASES = {"ErrImagePull": "ImagePullBackOff"}


def build_evidence(incident: dict[str, Any]) -> tuple[list[dict[str, str]], int, list[str]]:
    """Return redacted evidence items, the redaction count and prompt-injection warnings."""
    evidence: list[dict[str, str]] = []
    redactions = 0
    warnings: list[str] = []

    def add(kind: str, text: str) -> None:
        nonlocal redactions
        clean, count = redact(text[:MAX_EVIDENCE_CHARS])
        redactions += count
        item_id = f"{kind}:{sum(item['id'].startswith(kind + ':') for item in evidence) + 1}"
        evidence.append({"id": item_id, "text": clean})
        if _INJECTION.search(clean):
            warnings.append(f"Possible prompt injection in {item_id}; treated as data only.")

    for pod in incident.get("pods", []):
        for container in pod.get("containers", []):
            add(
                "pod",
                " ".join(
                    f"{key}={value}"
                    for key, value in {
                        "pod": pod.get("name"),
                        "phase": pod.get("phase"),
                        "container": container.get("name"),
                        "ready": container.get("ready"),
                        "restarts": container.get("restarts"),
                        "waiting": container.get("waiting_reason"),
                        "waiting_message": container.get("waiting_message"),
                        "terminated": container.get("terminated_reason"),
                        "last_terminated": container.get("last_terminated_reason"),
                        "last_exit_code": container.get("last_exit_code"),
                    }.items()
                    if value is not None
                ),
            )
        if not pod.get("containers"):
            add("pod", f"pod={pod.get('name')} phase={pod.get('phase')} containers=not-started")
        for line in pod.get("logs", [])[-MAX_LOG_LINES_PER_POD:]:
            add("log", line)
    for event in incident.get("events", []):
        add(
            "event",
            f"{event.get('type')} {event.get('reason')} object={event.get('object')} "
            f"count={event.get('count')} message={event.get('message')}",
        )
    return evidence, redactions, warnings


def _stable_pods(incident: dict[str, Any]) -> set[str]:
    """Pods that are fully ready and have never restarted."""
    return {
        pod["name"]
        for pod in incident.get("pods", [])
        if pod.get("containers")
        and all(c.get("ready") and not c.get("restarts") for c in pod["containers"])
    }


def detect_signals(
    incident: dict[str, Any], evidence: list[dict[str, str]], namespace: str
) -> list[dict[str, Any]]:
    """Find rule-based signals, each tied to the evidence items that show it."""
    found: dict[str, list[str]] = {}
    stable = _stable_pods(incident)
    for item in evidence:
        # Events outlive the problem, such as a probe failing during a Pod's normal startup.
        event_object = re.search(r"\bobject=(\S+)", item["text"])
        if item["id"].startswith("event:") and event_object and event_object.group(1) in stable:
            continue
        for token in re.findall(r"[A-Za-z]+", item["text"]):
            name = _ALIASES.get(token, token)
            if name in RULES and not item["id"].startswith("log:"):
                ids = found.setdefault(name, [])
                if item["id"] not in ids:
                    ids.append(item["id"])

    # A crash loop caused by the OOM killer is explained by the OOM signal first.
    ordered = [name for name in RULES if name in found]
    signals = []
    for name in ordered:
        rule = RULES[name]
        target = _affected_pod(found[name], evidence)
        signals.append(
            {
                "name": name,
                "runbook": rule.runbook,
                "cause": rule.cause,
                "query": rule.query,
                "claim": f"{name} was reported by the cluster for {target}.",
                "evidence": found[name],
                "steps": [
                    {
                        "text": "Inspect the Pod's status and recent events.",
                        "command": f"kubectl describe pod {target} -n {namespace}",
                    },
                    {
                        "text": "Read the logs from the previous container run.",
                        "command": f"kubectl logs {target} -n {namespace} --previous --tail=50",
                    },
                ],
            }
        )
    return signals


def _affected_pod(evidence_ids: list[str], evidence: list[dict[str, str]]) -> str:
    """Name the Pod from the evidence behind a signal, not simply the first Pod collected."""
    texts = {item["id"]: item["text"] for item in evidence}
    for item_id in evidence_ids:
        match = re.search(r"\b(?:pod|object)=(\S+)", texts[item_id])
        if match:
            return match.group(1)
    return "the affected Pod"


def validate_output(raw: str, evidence: list[dict[str, str]]) -> tuple[dict[str, Any], list[str]]:
    """Enforce the output contract. Uncited claims and non-read-only commands are removed."""
    data = json.loads(raw)
    if not isinstance(data, dict):
        raise ValueError("Provider output is not a JSON object")
    known = {item["id"] for item in evidence}
    rejected: list[str] = []

    claims = []
    for claim in data.get("claims", []):
        cited = claim.get("evidence") if isinstance(claim, dict) else None
        if isinstance(cited, list) and cited and all(item in known for item in cited):
            claims.append({"text": str(claim.get("text", "")), "evidence": cited})
        else:
            rejected.append(f"claim without valid evidence: {str(claim)[:120]}")

    steps = []
    for step in data.get("next_steps", []):
        if not isinstance(step, dict):
            rejected.append(f"malformed step: {str(step)[:120]}")
            continue
        command = step.get("command")
        if command is not None and (
            not _READ_ONLY_COMMAND.match(str(command)) or "secret" in str(command).lower()
        ):
            rejected.append(f"command is not read-only: {str(command)[:120]}")
            continue
        steps.append({"text": str(step.get("text", "")), "command": command})

    confidence = data.get("confidence")
    return (
        {
            "summary": str(data.get("summary", "")),
            "likely_cause": str(data.get("likely_cause", "")),
            "confidence": confidence if confidence in _CONFIDENCE else "low",
            "claims": claims,
            "next_steps": steps,
        },
        rejected,
    )


def analyze(
    incident: dict[str, Any], index: RunbookIndex, provider: Provider, budget: TokenBudget
) -> dict[str, Any]:
    namespace = str(incident.get("namespace", "default"))
    evidence, redactions, warnings = build_evidence(incident)
    signals = detect_signals(incident, evidence, namespace)
    # Search per signal in priority order, so the primary signal's runbook ranks first.
    hits: list[Hit] = []
    for signal in signals:
        for hit in index.search(signal["query"]):
            if hit.chunk.id not in {existing.chunk.id for existing in hits}:
                hits.append(hit)
    hits = hits[:MAX_RUNBOOK_HITS]
    runbooks = [
        {
            "id": hit.chunk.id,
            "score": f"{hit.score:.3f}",
            "text": redact(hit.chunk.text[:RUNBOOK_EXCERPT_CHARS])[0],
        }
        for hit in hits
    ]
    context = Context(signals=signals, evidence=evidence, runbooks=runbooks)
    prompt = build_prompt(context)
    tokens = estimate_tokens(prompt)
    result: dict[str, Any] = {
        "status": "ok",
        "provider": provider.name,
        "signals": [signal["name"] for signal in signals],
        "evidence": evidence,
        "runbooks": runbooks,
        "redactions": redactions,
        "warnings": warnings,
        "rejected": [],
        "estimated_prompt_tokens": tokens,
    }
    # Evidence is always returned, so an operator still has it when a provider step fails.
    try:
        budget.charge(tokens)
        output, rejected = validate_output(provider.complete(prompt, context), evidence)
    except BudgetExceeded as error:
        result.update(status="budget_exceeded", detail=str(error))
        return result
    except (ValueError, TypeError, AttributeError) as error:
        result.update(status="provider_error", detail=f"Invalid provider output: {error}")
        return result
    result.update(output)
    result["rejected"] = rejected
    if not signals:
        result["status"] = "no_incident"
    elif not output["claims"]:
        result["status"] = "insufficient_evidence"
    return result

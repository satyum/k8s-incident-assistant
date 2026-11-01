"""Evaluate the offline pipeline on synthetic incidents. Exits non-zero if a target is missed.

This measures signal detection, retrieval, citation integrity, privacy and cost controls.
It does not measure LLM answer quality, because no LLM is connected.
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

from assistant.analysis import analyze
from assistant.llm import MAX_PROMPT_TOKENS, StubProvider, TokenBudget
from assistant.retrieval import RunbookIndex

ROOT = Path(__file__).resolve().parent.parent
FAKE_SECRET = re.compile(r"FAKE-|FAKEtoken|admin@example\.com|10\.\d+\.\d+\.\d+")
# Raw error wording, searched directly, so retrieval is not only tested on the rule queries.
FREE_TEXT_QUERIES = {
    "Back-off restarting failed container": "crash-loop-backoff",
    "my pod keeps restarting and exits with code 1": "crash-loop-backoff",
    "Failed to pull image: manifest unknown": "image-pull-backoff",
    "registry returned unauthorized for the image": "image-pull-backoff",
    "container killed exit code 137 out of memory": "oom-killed",
    "0/3 nodes are available: 3 Insufficient cpu": "failed-scheduling",
    "pod stuck pending untolerated taint": "failed-scheduling",
    "Readiness probe failed: connect: connection refused": "probe-failure",
    "liveness probe timeout restarts container": "probe-failure",
    "pod is running but not ready": "probe-failure",
}
TARGETS = {
    "signal_accuracy": 1.0,
    "runbook_top1": 1.0,
    "free_text_top1": 0.8,
    "citation_validity": 1.0,
}


def main() -> int:
    samples = json.loads((ROOT / "samples" / "incidents.json").read_text(encoding="utf-8"))
    index = RunbookIndex(ROOT / "runbooks")
    provider = StubProvider()
    signal_hits = runbook_hits = runbook_total = cited = claims = leaks = over_budget = 0
    tokens = []
    for sample in samples:
        result = analyze(sample["incident"], index, provider, TokenBudget())
        signal_hits += result["signals"] == sample["expected_signals"]
        if sample["expected_runbook"]:
            runbook_total += 1
            top = result["runbooks"][0]["id"] if result["runbooks"] else ""
            runbook_hits += top.startswith(f"runbook:{sample['expected_runbook']}#")
        known = {item["id"] for item in result["evidence"]}
        for claim in result.get("claims", []):
            claims += 1
            cited += bool(claim["evidence"]) and set(claim["evidence"]) <= known
        leaks += len(FAKE_SECRET.findall(json.dumps(result)))
        tokens.append(result["estimated_prompt_tokens"])
        over_budget += result["estimated_prompt_tokens"] > MAX_PROMPT_TOKENS
    free_text_hits = 0
    for query, expected in FREE_TEXT_QUERIES.items():
        found = index.search(query, limit=1)
        hit = bool(found) and found[0].chunk.runbook == expected
        free_text_hits += hit
        if not hit:
            print(f"free-text miss: {query!r}")
    report = {
        "incidents": len(samples),
        "free_text_top1": round(free_text_hits / len(FREE_TEXT_QUERIES), 3),
        "signal_accuracy": round(signal_hits / len(samples), 3),
        "runbook_top1": round(runbook_hits / runbook_total, 3),
        "citation_validity": round(cited / claims, 3) if claims else 0.0,
        "secret_leaks": leaks,
        "over_budget_prompts": over_budget,
        "max_estimated_prompt_tokens": max(tokens),
    }
    print(json.dumps(report, indent=2))
    passed = (
        all(report[key] >= target for key, target in TARGETS.items())
        and leaks == 0
        and over_budget == 0
    )
    print("evaluation passed" if passed else "evaluation FAILED")
    return 0 if passed else 1


if __name__ == "__main__":
    sys.exit(main())

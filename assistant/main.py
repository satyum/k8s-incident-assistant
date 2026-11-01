"""Read-only incident analysis API."""

from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field

from assistant.analysis import analyze
from assistant.collector import CollectorError, KubernetesCollector
from assistant.llm import DEFAULT_DAILY_TOKEN_BUDGET, StubProvider, TokenBudget
from assistant.retrieval import RunbookIndex

_NAME = re.compile(r"^[a-z0-9]([-a-z0-9.]*[a-z0-9])?$")

index = RunbookIndex(Path(os.environ.get("RUNBOOK_DIR", "runbooks")))
provider = StubProvider()
budget = TokenBudget(int(os.environ.get("DAILY_TOKEN_BUDGET", DEFAULT_DAILY_TOKEN_BUDGET)))
collector = KubernetesCollector()
allowed_namespaces = set(filter(None, os.environ.get("ALLOWED_NAMESPACES", "").split(",")))

app = FastAPI(title="Kubernetes Incident Assistant", version="0.1.0")


class AnalyzeRequest(BaseModel):
    namespace: str = Field(max_length=63)
    workload: str | None = Field(default=None, max_length=63)


class SampleRequest(BaseModel):
    incident: dict[str, Any]


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "healthy"}


@app.post("/analyze")
def analyze_cluster(request: AnalyzeRequest) -> dict[str, Any]:
    """Collect read-only data from an allowed namespace and explain it."""
    if request.namespace not in allowed_namespaces:
        raise HTTPException(status_code=403, detail="Namespace is not allowed")
    if request.workload is not None and not _NAME.match(request.workload):
        raise HTTPException(status_code=422, detail="Invalid workload name")
    try:
        incident = collector.collect(request.namespace, request.workload)
    except CollectorError as error:
        raise HTTPException(status_code=502, detail=str(error)) from error
    return analyze(incident, index, provider, budget)


@app.post("/analyze/sample")
def analyze_sample(request: SampleRequest) -> dict[str, Any]:
    """Explain supplied incident data without contacting the cluster."""
    return analyze(request.incident, index, provider, budget)

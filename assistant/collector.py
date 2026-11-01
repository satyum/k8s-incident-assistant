"""Read-only collection of pods, events and logs from the Kubernetes API."""

from __future__ import annotations

import json
import ssl
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any

SERVICE_ACCOUNT = Path("/var/run/secrets/kubernetes.io/serviceaccount")
API_SERVER = "https://kubernetes.default.svc"
LOG_TAIL_LINES = 30


class CollectorError(RuntimeError):
    """The Kubernetes API could not provide the requested data."""


def normalize_pod(raw: dict[str, Any]) -> dict[str, Any]:
    containers = []
    for status in raw.get("status", {}).get("containerStatuses", []):
        state = status.get("state", {})
        last = status.get("lastState", {})
        containers.append(
            {
                "name": status.get("name", ""),
                "ready": status.get("ready", False),
                "restarts": status.get("restartCount", 0),
                "waiting_reason": state.get("waiting", {}).get("reason"),
                "waiting_message": state.get("waiting", {}).get("message"),
                "terminated_reason": state.get("terminated", {}).get("reason"),
                "last_terminated_reason": last.get("terminated", {}).get("reason"),
                "last_exit_code": last.get("terminated", {}).get("exitCode"),
            }
        )
    return {
        "name": raw.get("metadata", {}).get("name", ""),
        "phase": raw.get("status", {}).get("phase", "Unknown"),
        "containers": containers,
        "logs": [],
    }


def normalize_event(raw: dict[str, Any]) -> dict[str, Any]:
    return {
        "type": raw.get("type", ""),
        "reason": raw.get("reason", ""),
        "object": raw.get("involvedObject", {}).get("name", ""),
        "count": raw.get("count") or 1,
        "message": raw.get("message", ""),
    }


class KubernetesCollector:
    """Uses only GET requests with the Pod's service-account token."""

    def __init__(self, api_server: str = API_SERVER, account: Path = SERVICE_ACCOUNT) -> None:
        self._api = api_server
        self._account = account

    def _get(self, path: str, **params: Any) -> bytes:
        query = f"?{urllib.parse.urlencode(params)}" if params else ""
        try:
            token = (self._account / "token").read_text(encoding="utf-8").strip()
            context = ssl.create_default_context(cafile=str(self._account / "ca.crt"))
            request = urllib.request.Request(
                f"{self._api}{path}{query}", headers={"Authorization": f"Bearer {token}"}
            )
            with urllib.request.urlopen(request, context=context, timeout=10) as reply:
                return reply.read()
        except (OSError, urllib.error.URLError) as error:
            # The token is never part of this message, only the request failure.
            raise CollectorError(f"Kubernetes API request failed for {path}: {error}") from error

    def _logs(self, namespace: str, pod: str, container: str, previous: bool) -> list[str]:
        try:
            body = self._get(
                f"/api/v1/namespaces/{namespace}/pods/{pod}/log",
                container=container,
                tailLines=LOG_TAIL_LINES,
                previous=str(previous).lower(),
            )
        except CollectorError:
            return []
        return body.decode("utf-8", "replace").splitlines()

    def collect(self, namespace: str, workload: str | None = None) -> dict[str, Any]:
        pods_raw = json.loads(self._get(f"/api/v1/namespaces/{namespace}/pods"))["items"]
        events_raw = json.loads(self._get(f"/api/v1/namespaces/{namespace}/events"))["items"]
        pods = [normalize_pod(pod) for pod in pods_raw]
        events = [normalize_event(event) for event in events_raw]
        if workload:
            pods = [pod for pod in pods if pod["name"].startswith(workload)]
            events = [event for event in events if event["object"].startswith(workload)]
        for pod in pods:
            for container in pod["containers"]:
                previous = container["restarts"] > 0
                lines = self._logs(namespace, pod["name"], container["name"], previous)
                pod["logs"].extend(lines)
        return {"namespace": namespace, "pods": pods, "events": events}

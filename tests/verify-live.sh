#!/usr/bin/env bash
# Live check against real faults in incident-lab: detection, redaction and read-only access.
set -euo pipefail

K=(kubectl --context kind-local-platform)
SA=system:serviceaccount:incident-assistant:incident-assistant

for check in "delete pods" "create pods" "patch deployments" "get secrets"; do
  # shellcheck disable=SC2086
  if "${K[@]}" auth can-i $check -n incident-lab --as="$SA" >/dev/null 2>&1; then
    printf 'FAIL: service account can %s\n' "$check" >&2
    exit 1
  fi
done
if "${K[@]}" auth can-i get pods -n local-platform --as="$SA" >/dev/null 2>&1; then
  printf 'FAIL: service account can read another namespace\n' >&2
  exit 1
fi
"${K[@]}" auth can-i get pods/log -n incident-lab --as="$SA" >/dev/null
printf 'PASS: RBAC is read-only and limited to incident-lab\n'

"${K[@]}" -n incident-assistant port-forward svc/incident-assistant 18000:80 >/dev/null 2>&1 &
forward=$!
trap 'kill "$forward" 2>/dev/null || true' EXIT
sleep 4

python3 - <<'PY'
import json
import time
import urllib.error
import urllib.request

URL = "http://127.0.0.1:18000/analyze"
CASES = {
    "lab-crashloop": "CrashLoopBackOff",
    "lab-oom": "OOMKilled",
    "lab-bad-image": "ImagePullBackOff",
    "lab-unschedulable": "FailedScheduling",
    "lab-probe-failure": "Unhealthy",
}


def post(body):
    request = urllib.request.Request(
        URL, json.dumps(body).encode(), {"Content-Type": "application/json"}
    )
    with urllib.request.urlopen(request, timeout=20) as reply:
        return json.load(reply)


for workload, signal in CASES.items():
    deadline = time.time() + 240
    while True:
        result = post({"namespace": "incident-lab", "workload": workload})
        if signal in result["signals"]:
            break
        assert time.time() < deadline, f"FAIL: {workload} never showed {signal}: {result['signals']}"
        time.sleep(5)
    known = {item["id"] for item in result["evidence"]}
    assert result["claims"], f"FAIL: {workload} has no claims"
    assert all(set(c["evidence"]) <= known for c in result["claims"]), f"FAIL: {workload} citation"
    top = result["runbooks"][0]["id"]
    print(f"PASS: {workload}: {result['signals']}, top runbook {top}")

deadline = time.time() + 240
while True:
    crash = post({"namespace": "incident-lab", "workload": "lab-crashloop"})
    if crash["redactions"] and crash["warnings"]:
        break
    assert time.time() < deadline, "FAIL: crash-loop logs were not collected"
    time.sleep(5)
assert "FAKE-lab" not in json.dumps(crash), "FAIL: fake secret leaked"
print(f"PASS: fake secrets redacted ({crash['redactions']}) and injection flagged")
print(f"      {crash['warnings'][0]}")
assert not any("delete" in str(s["command"]) for s in crash["next_steps"])
print("PASS: injected delete command not followed")

healthy = post({"namespace": "incident-lab", "workload": "lab-healthy"})
assert healthy["status"] == "no_incident", f"FAIL: healthy workload: {healthy['signals']}"
print("PASS: healthy workload reports no_incident")

try:
    post({"namespace": "kube-system"})
    raise SystemExit("FAIL: namespace outside the allowlist was accepted")
except urllib.error.HTTPError as error:
    assert error.code == 403
print("PASS: namespace outside the allowlist returns 403")
print("All live checks passed")
PY

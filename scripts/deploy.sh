#!/usr/bin/env bash
# Build the assistant image and deploy it with the fault lab to the local kind cluster.
set -euo pipefail

KUBE_CONTEXT=kind-local-platform
IMAGE=incident-assistant:0.1.0
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
K=(kubectl --context "$KUBE_CONTEXT")
cd "$ROOT"

docker build -t "$IMAGE" .
kind load docker-image "$IMAGE" --name local-platform
"${K[@]}" apply -f k8s/lab.yaml
"${K[@]}" apply -f k8s/assistant.yaml
"${K[@]}" -n incident-assistant rollout status deploy/incident-assistant --timeout=120s

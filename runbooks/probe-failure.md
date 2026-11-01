# Probe failure

## Symptoms
An Unhealthy event reports Readiness probe failed or Liveness probe failed, often with connection refused or a timeout. The Pod is Running but not Ready, or its liveness restarts rise.

## Diagnosis
Check that the probe's port and path match what the application serves. Compare the probe timing with the application's startup time. Connection refused usually means nothing is listening on that port.

## Remediation
Correct the probe port or path, add a startup probe for slow starts, or fix the application endpoint.

# Container crash loop

## Symptoms
The Pod status shows CrashLoopBackOff, the restart count keeps rising and the kubelet reports Back-off restarting failed container. The container exits repeatedly shortly after it starts.

## Diagnosis
Read the logs from the previous container run with kubectl logs --previous. Check the last exit code in kubectl describe pod. Exit code 1 usually means an application error such as a failed connection or bad configuration.

## Remediation
Fix the application error or its configuration, then roll out the change. Do not remove the probe or restart policy to hide the failure.

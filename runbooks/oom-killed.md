# Out of memory kill

## Symptoms
The last terminated reason is OOMKilled with exit code 137. The Pod restarts and may then show CrashLoopBackOff, because the kernel killed a process that exceeded its memory limit.

## Diagnosis
Compare the container memory limit with its real usage. Check whether usage grows steadily, which suggests a leak, or spikes under load, which suggests a limit that is too low.

## Remediation
Raise the memory limit if the workload needs it, or fix the leak. Set requests and limits from observed usage.

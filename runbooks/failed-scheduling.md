# Pod cannot be scheduled

## Symptoms
The Pod stays Pending with no container statuses. A FailedScheduling event reports insufficient memory or insufficient cpu, untolerated taints or no nodes available.

## Diagnosis
Read the FailedScheduling event, which gives the reason for each node. Compare the Pod's requests with node allocatable capacity using kubectl describe node.

## Remediation
Lower excessive resource requests, add capacity, or correct the node selector, affinity or tolerations.

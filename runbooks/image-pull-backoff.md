# Image pull failure

## Symptoms
The Pod status shows ImagePullBackOff or ErrImagePull and the container never starts. Events report Failed to pull image, with no such host, not found or unauthorized.

## Diagnosis
Check the image name, registry and tag in the event message. A DNS failure or manifest not found points to a wrong reference. An unauthorized error points to missing registry credentials.

## Remediation
Correct the image reference, or add an imagePullSecret if the registry is private. For kind clusters, load local images with kind load docker-image.

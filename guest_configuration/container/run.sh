sudo podman run \
  --privileged \
  --rm \
  --device /dev/tpm0 \
  --mount type=bind,src=/sys/kernel/security/,target=/sys/kernel/security/ \
  --mount type=bind,src=/etc/kubernetes/node-feature-discovery/features.d,target=/nfd \
  guest-attest:0.2.0

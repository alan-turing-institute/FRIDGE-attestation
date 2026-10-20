sudo podman run \
  --privileged \
  --rm \
  --device /dev/tpm0 \
  --mount type=bind,src=/sys/kernel/security/,target=/sys/kernel/security/ \
  guest-attest:0.2.0 /usr/local/bin/azure-guest-attest guest-attest --provider maa

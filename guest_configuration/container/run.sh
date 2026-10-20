sudo podman run \
  --rm \
  --device /dev/tpm0 \
  --mount type=bind,src=/sys,target=/sys \
  guest-attest:0.2.0 /usr/local/bin/azure-guest-attest guest-attest --provider maa

# Azure Guest Attest Container

## Required access

Access to virtual files representing the TPM device and BIOS measurements is necessary for attestation.
TPM device at `/dev/tpm0`.
BIOS measurements at `/sys/kernel/security/tpm0/binary_bios_measurements`

For example

```console
sudo podman run \
  …
  --device /dev/tpm0 \
  --mount type=bind,src=/sys/kernel/security/,target=/sys/kernel/security/ \
  guest-attest:0.2.0
```

Mounting the parent `/sys/kernel/security` directory as we can't _create_ files in the kernels virtual filesystem (_e.g._ `mkdir /sys/kernel/security/tpm0`.

Possibly also `sys/kernel/security/tpm/binary_bios_measurements` and `/sys/firmaware/acpi/tables/data/TCG0`, but those don't appear to exist.

#!/usr/bin/env bash
set -e

while true; do
  azure-guest-attest guest-attest --provider "$PROVIDER" --out result
  write-feature
  sleep 12h
done

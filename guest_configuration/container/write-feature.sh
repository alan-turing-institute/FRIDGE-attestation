#!/usr/bin/env bash
# Take "Token" line from guest-attest output and prepare for a NFD local
# feature source in the format feature.node.kubernetes.io/feature.item: "value"
# https://kubernetes-sigs.github.io/node-feature-discovery/master/usage/customization-guide.html#local-feature-source
cat result | grep Token | sed 's/Token.*:\s\(.*\)$/feature\.node\.kubernetes\.io\/attestation\.report: "\1"/' > /nfd/attestation

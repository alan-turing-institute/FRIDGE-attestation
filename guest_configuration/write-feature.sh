#!usr/bin/env bash
cat result | grep Token | sed 's/Token.*:\s\(.*\)$/feature\.node\.kubernetes\.io\/attestation\.report: "\1"/' > /nfd/attestation

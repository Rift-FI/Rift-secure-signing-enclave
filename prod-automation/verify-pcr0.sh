#!/usr/bin/env bash
# verify-pcr0.sh — proves the enclave you just built is the code Rift
# ships. Fetches Rift's canonical PCR0 for the pinned ENCLAVE_REF and
# compares against your locally-built PCR0.
#
# Run this BEFORE pasting your PCR0 into your KMS key policy. If it
# doesn't match, do not proceed — either you built from a different
# ref, or your build environment differs (in which case Rift needs to
# publish a PCR0 for your build config), or something is very wrong.
#
# Reproducibility promise: Rift publishes PCR0s per released tag at
#   https://riftfi.com/enclave/pcr0/<tag>.txt        (raw hex)
#   https://riftfi.com/enclave/pcr0/<tag>.json       (metadata)
# built via Rift's own CI pipeline on public runners. If your locally
# built PCR0 matches, the code you're running is byte-identical to the
# code Rift ships.
#
# USAGE:
#   ENCLAVE_REF=v1.0.0 PCR0=<96-hex> ./verify-pcr0.sh
# or, if you just ran ec2-bootstrap.sh:
#   ./verify-pcr0.sh                     # reads $HOME/rift/state.json

set -Eeuo pipefail

STATE="${STATE:-$HOME/rift/state.json}"

if [[ -z "${ENCLAVE_REF:-}" || -z "${PCR0:-}" ]]; then
  if [[ -r "$STATE" ]]; then
    ENCLAVE_REF="${ENCLAVE_REF:-$(jq -r .enclave_ref "$STATE")}"
    PCR0="${PCR0:-$(jq -r .pcr0 "$STATE")}"
  fi
fi

: "${ENCLAVE_REF:?set ENCLAVE_REF (git tag)}"
: "${PCR0:?set PCR0 (96 hex chars)}"

if [[ "$ENCLAVE_REF" == "main" || "$ENCLAVE_REF" == "master" ]]; then
  echo "─────────────────────────────────────────────────────────────"
  echo "  ENCLAVE_REF is a moving branch."
  echo "  Rift does not publish PCR0s for moving branches; PCR0 is"
  echo "  only reproducible for pinned tags."
  echo
  echo "  If you're doing sandbox / dev work, this is fine — skip"
  echo "  verification but DO NOT run this build in production."
  echo
  echo "  If you're doing production, rebuild with a pinned tag:"
  echo "    ENCLAVE_REF=v1.0.0 /tmp/ec2-bootstrap.sh"
  echo "─────────────────────────────────────────────────────────────"
  exit 2
fi

URL="https://riftfi.com/enclave/pcr0/${ENCLAVE_REF}.txt"
echo "fetching canonical PCR0 for ${ENCLAVE_REF} …"
CANONICAL=$(curl -fsS --max-time 10 "$URL" | tr -d '[:space:]' || true)

if [[ -z "$CANONICAL" ]]; then
  echo "─────────────────────────────────────────────────────────────"
  echo "  could not fetch $URL"
  echo
  echo "  either the tag hasn't been published yet, or you have"
  echo "  no network from this host. If you're offline in an"
  echo "  isolated VPC, download the PCR0 file from a machine"
  echo "  with internet and pass it in:"
  echo
  echo "    CANONICAL_PCR0=<hex> ./verify-pcr0.sh"
  echo "─────────────────────────────────────────────────────────────"
  if [[ -n "${CANONICAL_PCR0:-}" ]]; then
    CANONICAL="$(echo "$CANONICAL_PCR0" | tr -d '[:space:]')"
  else
    exit 3
  fi
fi

LOCAL=$(echo "$PCR0" | tr -d '[:space:]')

echo
echo "  ref       : $ENCLAVE_REF"
echo "  canonical : $CANONICAL"
echo "  local     : $LOCAL"
echo

if [[ "${LOCAL,,}" == "${CANONICAL,,}" ]]; then
  echo "  ✓ MATCH — the enclave you built is Rift's canonical build."
  echo "    safe to pin this PCR0 into your KMS policy."
  exit 0
else
  echo "  ✗ MISMATCH — do NOT pin this PCR0 into a production key policy."
  echo
  echo "  possible causes:"
  echo "    * you're on a different toolchain / base image than Rift's CI"
  echo "    * you've applied a patch to the enclave source"
  echo "    * the repo you cloned isn't Rift's (verify the git remote)"
  echo "    * the tag was retagged (rare, check Rift's release notes)"
  echo
  echo "  if you intentionally forked, publish your own PCR0 alongside"
  echo "  your fork and skip this check."
  exit 1
fi

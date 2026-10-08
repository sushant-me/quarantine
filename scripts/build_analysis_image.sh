#!/usr/bin/env bash
# Build the analysis image used for artifacts whose custom code imports torch/transformers.
#
#   ./scripts/build_analysis_image.sh
#
# Then analysis picks it up automatically (see sandbox/execute.py::resolve_image), or you
# can force it with QUARANTINE_IMAGE=quarantine-analysis:latest. Every receipt records the
# image it ran in, so a result is never ambiguous about which box produced it.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TAG="${TAG:-quarantine-analysis:latest}"

echo "building $TAG from docker/Dockerfile.analysis"
echo "(CPU-only torch plus transformers: a few hundred MB of download, once)"
docker build -f "$ROOT/docker/Dockerfile.analysis" -t "$TAG" "$ROOT/docker"

echo
docker image inspect "$TAG" --format 'built {{.RepoTags}} size={{.Size}} id={{.Id}}' | cut -c1-120
echo "analysis will now prefer this image; the base python:3.12-slim remains the fallback"

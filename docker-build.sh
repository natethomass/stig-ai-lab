#!/bin/bash
# =============================================================
# docker-build.sh — Build all STIG AI Lab images
# =============================================================

set -euo pipefail

TAG="${1:-latest}"
REGISTRY="${REGISTRY:-stig-ai-lab}"

echo "Building STIG AI Lab images (tag: $TAG)..."

images=(scanner analyst remediation compliance orchestrator)

for image in "${images[@]}"; do
    echo ""
    echo "──────────────────────────────────────"
    echo "Building: $REGISTRY/$image:$TAG"
    echo "──────────────────────────────────────"
    docker build \
        -t "$REGISTRY/$image:$TAG" \
        -f "docker/$image/Dockerfile" \
        .
    echo "✓ $image built"
done

echo ""
echo "All images built successfully:"
for image in "${images[@]}"; do
    echo "  $REGISTRY/$image:$TAG"
done

echo ""
echo "To start the lab:"
echo "  docker compose up -d"
echo ""
echo "To run an interactive hardening session:"
echo "  docker compose run --rm orchestrator"
echo ""
echo "To scale the analyst agent (e.g. 3 instances):"
echo "  docker compose up -d --scale analyst=3"

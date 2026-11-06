#!/usr/bin/env bash
set -euo pipefail
for ns in pc1 device1 device2 pc2; do
  ip netns del "$ns" 2>/dev/null || true
done
echo "Lab namespaces removed."

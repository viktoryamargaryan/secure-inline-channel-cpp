#!/usr/bin/env bash
set -euo pipefail
for ns in device1 device2; do
  ip netns exec "$ns" iptables -D FORWARD -s 10.0.1.2 -d 10.0.3.2 -p tcp --dport 5001 -j NFQUEUE --queue-num 0 2>/dev/null || true
  ip netns exec "$ns" iptables -t raw -D PREROUTING -s 10.0.1.2 -d 10.0.3.2 -p tcp --dport 5001 -j NOTRACK 2>/dev/null || true
  ip netns exec "$ns" iptables -t raw -D PREROUTING -s 10.0.3.2 -d 10.0.1.2 -p tcp --sport 5001 -j NOTRACK 2>/dev/null || true
done
echo "NFQUEUE and NOTRACK rules removed."

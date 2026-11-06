#!/usr/bin/env bash
set -euo pipefail

# Run as root AFTER both secure_inline processes print READY.
# NOTRACK is used for this lab flow because the middle packet's TCP payload
# is temporarily 28 bytes longer. End hosts still see the original TCP stream.
for ns in device1 device2; do
  ip netns exec "$ns" iptables -t raw -C PREROUTING -s 10.0.1.2 -d 10.0.3.2 -p tcp --dport 5001 -j NOTRACK 2>/dev/null || \
    ip netns exec "$ns" iptables -t raw -I PREROUTING 1 -s 10.0.1.2 -d 10.0.3.2 -p tcp --dport 5001 -j NOTRACK
  ip netns exec "$ns" iptables -t raw -C PREROUTING -s 10.0.3.2 -d 10.0.1.2 -p tcp --sport 5001 -j NOTRACK 2>/dev/null || \
    ip netns exec "$ns" iptables -t raw -I PREROUTING 1 -s 10.0.3.2 -d 10.0.1.2 -p tcp --sport 5001 -j NOTRACK
  ip netns exec "$ns" iptables -C FORWARD -s 10.0.1.2 -d 10.0.3.2 -p tcp --dport 5001 -j NFQUEUE --queue-num 0 2>/dev/null || \
    ip netns exec "$ns" iptables -I FORWARD 1 -s 10.0.1.2 -d 10.0.3.2 -p tcp --dport 5001 -j NFQUEUE --queue-num 0
done

echo "NOTRACK and NFQUEUE rules enabled on Device1 and Device2."

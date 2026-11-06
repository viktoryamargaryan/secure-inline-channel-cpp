#!/usr/bin/env bash
set -euo pipefail

# Run as root. Creates PC1 -- Device1 -- Device2 -- PC2 using network namespaces.
for ns in pc1 device1 device2 pc2; do
  ip netns del "$ns" 2>/dev/null || true
  ip netns add "$ns"
done

ip link add pc1v type veth peer name d1v0
ip link add d1v1 type veth peer name d2v0
ip link add d2v1 type veth peer name pc2v

ip link set pc1v netns pc1
ip link set d1v0 netns device1
ip link set d1v1 netns device1
ip link set d2v0 netns device2
ip link set d2v1 netns device2
ip link set pc2v netns pc2

ip -n pc1 link set pc1v name eth0
ip -n device1 link set d1v0 name eth0
ip -n device1 link set d1v1 name eth1
ip -n device2 link set d2v0 name eth0
ip -n device2 link set d2v1 name eth1
ip -n pc2 link set pc2v name eth0

for ns in pc1 device1 device2 pc2; do
  ip -n "$ns" link set lo up
done

# Host-facing links use MTU 2000. The Device1<->Device2 link uses 2100,
# leaving room for the 28-byte nonce+tag expansion of a maximum-sized segment.
for spec in "pc1 eth0 2000" "device1 eth0 2000" "device1 eth1 2100" \
            "device2 eth0 2100" "device2 eth1 2000" "pc2 eth0 2000"; do
  read -r ns iface mtu <<< "$spec"
  ip -n "$ns" link set "$iface" mtu "$mtu"
  ip -n "$ns" link set "$iface" up
done

ip -n pc1 addr add 10.0.1.2/24 dev eth0
ip -n device1 addr add 10.0.1.1/24 dev eth0
ip -n device1 addr add 10.0.2.1/24 dev eth1
ip -n device2 addr add 10.0.2.2/24 dev eth0
ip -n device2 addr add 10.0.3.1/24 dev eth1
ip -n pc2 addr add 10.0.3.2/24 dev eth0

ip -n pc1 route add default via 10.0.1.1
ip -n pc2 route add default via 10.0.3.1
ip -n device1 route add 10.0.3.0/24 via 10.0.2.2
ip -n device2 route add 10.0.1.0/24 via 10.0.2.1

for ns in device1 device2; do
  ip netns exec "$ns" sysctl -qw net.ipv4.ip_forward=1
  ip netns exec "$ns" sysctl -qw net.ipv4.conf.all.rp_filter=0
  ip netns exec "$ns" sysctl -qw net.ipv4.conf.default.rp_filter=0
done

# Disable common offloads in the lab if ethtool is installed.
if command -v ethtool >/dev/null 2>&1; then
  for spec in "device1 eth0" "device1 eth1" "device2 eth0" "device2 eth1"; do
    read -r ns iface <<< "$spec"
    ip netns exec "$ns" ethtool -K "$iface" gro off gso off tso off 2>/dev/null || true
  done
fi

echo "Lab created. Test basic routing with: ip netns exec pc1 ping -c 2 10.0.3.2"

#!/bin/bash
set -eux

NSIPV4=ipv4
NSIPV6=ipv6

LINK_IPV4=veth-host4
LINK_IPV6=veth-host6

# Cleanup old namespaces and veths if they exist
ip netns del $NSIPV4 2>/dev/null || true
ip netns del $NSIPV6 2>/dev/null || true
ip link del $LINK_IPV4 2>/dev/null || true
ip link del $LINK_IPV6 2>/dev/null || true

# Create network namespaces
ip netns add $NSIPV4
ip netns add $NSIPV6

ip link add $LINK_IPV4 type veth peer name eth0
ip link set eth0 netns $NSIPV4

ip link add $LINK_IPV6 type veth peer name eth0
ip link set eth0 netns $NSIPV6

# Setup host side of veth pairs and bring up
ip addr add 192.168.100.1/24 dev $LINK_IPV4
ip link set $LINK_IPV4 up

ip -6 addr add fd00:dead:beef::1/64 dev $LINK_IPV6
ip link set $LINK_IPV6 up

# Setup namespace side interfaces and IPs and routes
ip netns exec $NSIPV4 ip addr add 192.168.100.2/24 dev eth0
ip netns exec $NSIPV4 ip link set eth0 up
ip netns exec $NSIPV4 ip link set lo up
ip netns exec $NSIPV4 ip route add default via 192.168.100.1

ip netns exec $NSIPV6 ip -6 addr add fd00:dead:beef::2/64 dev eth0
ip netns exec $NSIPV6 ip link set eth0 up
ip netns exec $NSIPV6 ip link set lo up
ip netns exec $NSIPV6 ip -6 route add default via fd00:dead:beef::1

# Address Resolution Protocol (ARP)

The Address Resolution Protocol (ARP) is a fundamental building block for neighboring systems in which a system can discover the MAC address (L2) associated with an IPv4 (L3) address.

In short, ARP is implemented by broadcasting 'who has' packets to all devices connected to the NIC, as established by the default routing table. This message is a broadcast message, and thus the destination MAC address is FF::FF (FF repeated). As such, the message traverses the broadcast domain of the network. When a machine with the IP address is found, it returns a "is at" message. For all other machines, the packet is dropped.

A *broadcast domain* is a network segment where all devices can receive a broadcast message sent by any device within it. It's typically a single LAN or VLAN where a broadcast frame, like an ARP request, reaches every device.

Routers separate broadcast domains, limiting the scope of these messages. Routers do not forward ARP packets beyond their broadcast domain. When a router receives an ARP request, it processes it only if the target IP matches its own interface. Otherwise, it discards the packet. ARP operates within a single broadcast domain (like a LAN or VLAN), so routers, which separate these domains, limit ARP traffic to local networks. If a device needs to communicate outside its domain, the router uses its own MAC address as the gateway in the ARP response.

### Hands On 

Given the docker-compose.yml file, we can bring up an env that simply demostrates ARP in a network
The docker compose command creates 4 containers total. Node[1-3] are running on the same network, while Node4 is on a different network.

```bash
$ docker-compose up -d
$ docker ps
CONTAINER ID   IMAGE               COMMAND                  CREATED              STATUS              PORTS     NAMES
8b28555595a0   nicolaka/netshoot   "/bin/sh -c 'tcpdump…"   About a minute ago   Up About a minute             node3
531fbabcf0e9   nicolaka/netshoot   "/bin/sh -c 'tcpdump…"   About a minute ago   Up About a minute             node4
2d86c3c2f3d8   nicolaka/netshoot   "/bin/sh -c 'tcpdump…"   About a minute ago   Up About a minute             node1
5b33d2e9257e   nicolaka/netshoot   "/bin/sh -c 'tcpdump…"   About a minute ago   Up About a minute             node2
```

Ill ping node3 from node1

```bash
$ docker exec -it node1 ping -c3 node3
PING node3 (172.28.0.13) 56(84) bytes of data.
64 bytes from node3.arp_lan (172.28.0.13): icmp_seq=1 ttl=64 time=0.067 ms
64 bytes from node3.arp_lan (172.28.0.13): icmp_seq=2 ttl=64 time=0.038 ms
64 bytes from node3.arp_lan (172.28.0.13): icmp_seq=3 ttl=64 time=0.051 ms

--- node3 ping statistics ---
3 packets transmitted, 3 received, 0% packet loss, time 2054ms
rtt min/avg/max/mdev = 0.038/0.052/0.067/0.011 ms
```

Now if we look at the tcpdump output, we can see the ARP request and response packets:

```bash
$ tcpdump -r pcaps/node1.pcap -p arp or icmp
reading from file pcaps/node1.pcap, link-type EN10MB (Ethernet), snapshot length 262144
21:14:12.893963 ARP, Request who-has 172.28.0.13 tell 172.28.0.11, length 28
21:14:12.894004 ARP, Reply 172.28.0.13 is-at 02:42:ac:1c:00:0d (oui Unknown), length 28
21:14:12.894006 IP 172.28.0.11 > 172.28.0.13: ICMP echo request, id 5, seq 1, length 64
21:14:12.894018 IP 172.28.0.13 > 172.28.0.11: ICMP echo reply, id 5, seq 1, length 64
21:14:13.917567 IP 172.28.0.11 > 172.28.0.13: ICMP echo request, id 5, seq 2, length 64
21:14:13.917589 IP 172.28.0.13 > 172.28.0.11: ICMP echo reply, id 5, seq 2, length 64
21:14:14.941558 IP 172.28.0.11 > 172.28.0.13: ICMP echo request, id 5, seq 3, length 64
21:14:14.941579 IP 172.28.0.13 > 172.28.0.11: ICMP echo reply, id 5, seq 3, length 64
21:14:18.077544 ARP, Request who-has 172.28.0.11 tell 172.28.0.13, length 28
21:14:18.077550 ARP, Reply 172.28.0.11 is-at 02:42:ac:1c:00:0b (oui Unknown), length 28 


$ docker exec -it node1 ip a show
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
    inet6 ::1/128 scope host 
       valid_lft forever preferred_lft forever
71: eth0@if72: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UP group default 
    link/ether 02:42:ac:1c:00:0b brd ff:ff:ff:ff:ff:ff link-netnsid 0
    inet 172.28.0.11/16 brd 172.28.255.255 scope global eth0
       valid_lft forever preferred_lft forever

$ docker exec -it node3 ip a show
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
    inet6 ::1/128 scope host 
       valid_lft forever preferred_lft forever
73: eth0@if74: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UP group default 
    link/ether 02:42:ac:1c:00:0d brd ff:ff:ff:ff:ff:ff link-netnsid 0
    inet 172.28.0.13/16 brd 172.28.255.255 scope global eth0
       valid_lft forever preferred_lft forever

```

What the above tells us is, node1 broadcasts a "who-has" request to everyon in the network. For those who dont care about the request, they recieve it but drop it. Node3, however, sees that the request is for its IP address, and responds with an "is-at" message, which contains its MAC address. Node1 then sends an ICMP echo request to node3, which node3 replies to.

```bash
$ tcpdump -r pcaps/node1.pcap -p arp or icmp
reading from file pcaps/node1.pcap, link-type EN10MB (Ethernet), snapshot length 262144
21:14:12.893963 ARP, Request who-has 172.28.0.13 tell 172.28.0.11, length 28
21:14:12.894004 ARP, Reply 172.28.0.13 is-at 02:42:ac:1c:00:0d (oui Unknown), length 28
21:14:12.894006 IP 172.28.0.11 > 172.28.0.13: ICMP echo request, id 5, seq 1, length 64
21:14:12.894018 IP 172.28.0.13 > 172.28.0.11: ICMP echo reply, id 5, seq 1, length 64
21:14:13.917567 IP 172.28.0.11 > 172.28.0.13: ICMP echo request, id 5, seq 2, length 64
21:14:13.917589 IP 172.28.0.13 > 172.28.0.11: ICMP echo reply, id 5, seq 2, length 64
21:14:14.941558 IP 172.28.0.11 > 172.28.0.13: ICMP echo request, id 5, seq 3, length 64
21:14:14.941579 IP 172.28.0.13 > 172.28.0.11: ICMP echo reply, id 5, seq 3, length 64

$ tcpdump -r pcaps/node2.pcap -p arp or icmp
reading from file pcaps/node2.pcap, link-type EN10MB (Ethernet), snapshot length 262144
21:14:12.893984 ARP, Request who-has 172.28.0.13 tell 172.28.0.11, length 28 

$ tcpdump -r pcaps/node3.pcap -p arp or icmp
reading from file pcaps/node3.pcap, link-type EN10MB (Ethernet), snapshot length 262144
21:14:12.893982 ARP, Request who-has 172.28.0.13 tell 172.28.0.11, length 28
21:14:12.893998 ARP, Reply 172.28.0.13 is-at 02:42:ac:1c:00:0d (oui Unknown), length 28
21:14:12.894007 IP 172.28.0.11 > 172.28.0.13: ICMP echo request, id 5, seq 1, length 64
21:14:12.894017 IP 172.28.0.13 > 172.28.0.11: ICMP echo reply, id 5, seq 1, length 64
21:14:13.917575 IP 172.28.0.11 > 172.28.0.13: ICMP echo request, id 5, seq 2, length 64
21:14:13.917587 IP 172.28.0.13 > 172.28.0.11: ICMP echo reply, id 5, seq 2, length 64
21:14:14.941566 IP 172.28.0.11 > 172.28.0.13: ICMP echo request, id 5, seq 3, length 64
21:14:14.941577 IP 172.28.0.13 > 172.28.0.11: ICMP echo reply, id 5, seq 3, length 64
```

If we look at the ARP table on each node, we can see that Node1 and Node3 have each other's MAC address, while Node2 and Node4 do not have any entries in their ARP tables.

```bash
$ docker exec -it node1 arp -a
node3.arp_lan (172.28.0.13) at 02:42:ac:1c:00:0d [ether]  on eth0
$ docker exec -it node3 arp -a
node1.arp_lan (172.28.0.11) at 02:42:ac:1c:00:0b [ether]  on eth0
$ docker exec -it node2 arp -a
$ docker exec -it node4 arp -a
```

Node4 is on a compeltely different network, so it does not see the ARP request or response packets.

```bash
$ tcpdump -r pcaps/node4.pcap -p arp or icmp
reading from file pcaps/node4.pcap, link-type EN10MB (Ethernet), snapshot length 262144
```

If we look at the routing table on Node4 vs Node1 and Node3, we can see that Node4 has a different default route than Node1 and Node3.

```bash
$ docker exec -it node4 ip route show
default via 172.18.0.1 dev eth0 
172.18.0.0/16 dev eth0 proto kernel scope link src 172.18.0.2 

$ docker exec -it node1 ip route show
default via 172.28.0.1 dev eth0 
172.28.0.0/16 dev eth0 proto kernel scope link src 172.28.0.11 
$ docker exec -it node3 ip route show
default via 172.28.0.1 dev eth0 
172.28.0.0/16 dev eth0 proto kernel scope link src 172.28.0.13
```

From my host, we can see the default gateway for the containers maps to the bridge interfaces created by Docker.

```bash
$ ip a show
65: br-0aa1f004b089: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UP group default 
    link/ether 02:42:0c:da:3c:6e brd ff:ff:ff:ff:ff:ff
    inet 172.28.0.1/16 brd 172.28.255.255 scope global br-0aa1f004b089
       valid_lft forever preferred_lft forever
    inet6 fe80::42:cff:feda:3c6e/64 scope link 
       valid_lft forever preferred_lft forever
66: br-11526a4bc97d: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UP group default 
    link/ether 02:42:97:fc:e5:79 brd ff:ff:ff:ff:ff:ff
    inet 172.18.0.1/16 brd 172.18.255.255 scope global br-11526a4bc97d
       valid_lft forever preferred_lft forever
    inet6 fe80::42:97ff:fefc:e579/64 scope link 
       valid_lft forever preferred_lft forever
```

Digging further into this experiment, we can peer into what Linux is actually doing. By using the 'perf' tool, we can view tracepoints related to networking, niegh, and bridge traffic. Ill go through the following ping trace section by section, and explain what is happening.

The traces pertain the the following network stack. Ignore the ones from above, as these were taken from a new session.

```bash


$ docker exec -it node1 ip a show
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
    inet6 ::1/128 scope host 
       valid_lft forever preferred_lft forever
101: eth0@if102: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UP group default 
    link/ether 02:42:ac:1c:00:0b brd ff:ff:ff:ff:ff:ff link-netnsid 0
    inet 172.28.0.11/16 brd 172.28.255.255 scope global eth0
       valid_lft forever preferred_lft forever

$ docker exec -it node2 ip a show
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
    inet6 ::1/128 scope host 
       valid_lft forever preferred_lft forever
103: eth0@if104: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UP group default 
    link/ether 02:42:ac:1c:00:0c brd ff:ff:ff:ff:ff:ff link-netnsid 0
    inet 172.28.0.12/16 brd 172.28.255.255 scope global eth0
       valid_lft forever preferred_lft forever

$ docker exec -it node3 ip a show
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
    inet6 ::1/128 scope host 
       valid_lft forever preferred_lft forever
97: eth0@if98: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UP group default 
    link/ether 02:42:ac:1c:00:0d brd ff:ff:ff:ff:ff:ff link-netnsid 0
    inet 172.28.0.13/16 brd 172.28.255.255 scope global eth0
       valid_lft forever preferred_lft forever

$ docker exec -it node4 ip a show
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
    inet6 ::1/128 scope host 
       valid_lft forever preferred_lft forever
99: eth0@if100: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UP group default 
    link/ether 02:42:ac:12:00:02 brd ff:ff:ff:ff:ff:ff link-netnsid 0
    inet 172.18.0.2/16 brd 172.18.255.255 scope global eth0
       valid_lft forever preferred_lft forever

95: br-9bfe50b3a208: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UP group default 
    link/ether 02:42:d6:22:5a:c4 brd ff:ff:ff:ff:ff:ff
    inet 172.18.0.1/16 brd 172.18.255.255 scope global br-9bfe50b3a208
       valid_lft forever preferred_lft forever
    inet6 fe80::42:d6ff:fe22:5ac4/64 scope link 
       valid_lft forever preferred_lft forever
96: br-23bc52c38b4c: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UP group default 
    link/ether 02:42:8e:ff:44:b3 brd ff:ff:ff:ff:ff:ff
    inet 172.28.0.1/16 brd 172.28.255.255 scope global br-23bc52c38b4c
       valid_lft forever preferred_lft forever
    inet6 fe80::42:8eff:feff:44b3/64 scope link 
       valid_lft forever preferred_lft forever
98: vethf330287@if97: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue master br-23bc52c38b4c state UP group default 
    link/ether 1a:b3:dc:78:ab:93 brd ff:ff:ff:ff:ff:ff link-netnsid 0
    inet6 fe80::18b3:dcff:fe78:ab93/64 scope link 
       valid_lft forever preferred_lft forever
100: veth212d7c8@if99: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue master br-9bfe50b3a208 state UP group default 
    link/ether ca:0d:f0:da:02:5f brd ff:ff:ff:ff:ff:ff link-netnsid 1
    inet6 fe80::c80d:f0ff:feda:25f/64 scope link 
       valid_lft forever preferred_lft forever
102: veth2f068b3@if101: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue master br-23bc52c38b4c state UP group default 
    link/ether 2a:12:20:49:fc:b5 brd ff:ff:ff:ff:ff:ff link-netnsid 3
    inet6 fe80::2812:20ff:fe49:fcb5/64 scope link 
       valid_lft forever preferred_lft forever
104: vethb069b0f@if103: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue master br-23bc52c38b4c state UP group default 
    link/ether 0e:67:6b:49:1e:5b brd ff:ff:ff:ff:ff:ff link-netnsid 2
    inet6 fe80::c67:6bff:fe49:1e5b/64 scope link 
       valid_lft forever preferred_lft forever
```

First we can see a neigh_create tracepoint. This initializes the neighbor entry for the destination IP address. We then see the packet being queued for transmission on the device. The `net_dev_queue` tracepoint indicates that the packet is being prepared for sending followed by a transmit (xmit) trace for the actual send.

```bash
1857097.663762:               neigh:neigh_create: family 2 dev eth0 entries 17 primary_key4 172.28.0.13 primary_key6 :: created 1 gc_exempt 0
1857097.663773:                net:net_dev_queue: dev=eth0 skbaddr=0xffff9e25e838e700x len=42
1857097.663783:           net:net_dev_start_xmit: dev=eth0 queue_mapping=0 skbaddr=0xffff9e25e838e700 vlan_tagged=0 vlan_proto=0x0000 vlan_tci=0x0000 protocol=0x0806
```

Next we see the recieve (rx) tracepoints for the veth pair device on the host. One interesting aspect of container networking is traversal from container to host on a veth pair still requires the request to go through the per-CPU network queue. This is because the veth pair is treated like any other network interface in the Linux kernel. However, with eBPF and dynamic kernel extencibility, one could imagine a more efficient way to handle this, such as bypassing the per-CPU queue for veth pairs via some custom eBPF program that directly processes packets to their host local endpoints.

```bash
1857097.663789:               net:netif_rx_entry: dev=veth2f068b3 napi_id=0x3 queue_mapping=0 skbaddr=0xffff9e25e838e700 vlan_tagged=0 vlan_proto=0x0000 vlan_tci=0x0000 protocol=0x0806 ip_summ>
1857097.663796:               net:netif_rx: dev=veth2f068b3 skbaddr=0xffff9e25e838e700x len=28
1857097.663803:               net:netif_rx_exit: ret=0
1857097.663822:               net:netif_receive_skb: dev=veth2f068b3 skbaddr=0xffff9e25e838e700x len=28
```

Next we see the bridge processing the packet. The `br_fdb_update` tracepoint indicates that the bridge is updating its forwarding database (FDB) with the source MAC address and associated port. This is crucial for the bridge to know where to send future packets destined for that MAC address.

```bash
1857097.663830:             bridge:br_fdb_update: br_dev br-23bc52c38b4c source veth2f068b3 addr 02:42:ac:1c:00:0b vid 0 flags 0x0
```

Below, we see a packet make its way to Node2's host veth interface. The ARP request was broadacsted to all recipients but since Node2 does not care to respond, it simply drops the packet after it is recieved on the eth0 interface in the containers network namespace.

```bash
1857097.663849:                net:net_dev_queue: dev=vethb069b0f skbaddr=0xffff9e25e838ff00x len=42
1857097.663856:                net:net_dev_start_xmit: dev=vethb069b0f queue_mapping=0 skbaddr=0xffff9e25e838ff00 vlan_tagged=0 vlan_proto=0x0000 vlan_tci=0x0000 protocol=0x0806 ip_summed=0
1857097.663863:                net:netif_rx_entry: dev=eth0 napi_id=0x3 queue_mapping=0 skbaddr=0xffff9e25e838ff00 vlan_tagged=0 vlan_proto=0x0000 vlan_tci=0x0000 protocol=0x0806 ip_summed=0
1857097.663870:                net:netif_rx: dev=eth0 skbaddr=0xffff9e25e838ff00x len=28
1857097.663877:                net:netif_rx_exit: ret=0
1857097.663883:                net:net_dev_xmit: dev=vethb069b0f skbaddr=0xffff9e25e838ff00 len=42 rc=0
```

We also see it queue up in Node3's host veth interface and make its way to the containers eth0 interface.

```bash
1857097.663888:                net:net_dev_queue: dev=vethf330287 skbaddr=0xffff9e25e838f100x len=42
1857097.663893:                net:net_dev_start_xmit: dev=vethf330287 queue_mapping=0 skbaddr=0xffff9e25e838f100 vlan_tagged=0 vlan_proto=0x0000 
1857097.663899:                net:netif_rx_entry: dev=eth0 napi_id=0x3 queue_mapping=0 skbaddr=0xffff9e25e838f100 vlan_tagged=0 vlan_proto=0x0000 
1857097.663904:                net:netif_rx: dev=eth0 skbaddr=0xffff9e25e838f100x len=28
1857097.663909:                net:netif_rx_exit: ret=0
1857097.663914:                net:net_dev_xmit: dev=vethf330287 skbaddr=0xffff9e25e838f100 len=42 rc=0
```

The containers netif_recieve_skb tracepoint indicates that the packet is being processed by the network stack in the container's network namespace. This is where the ARP request is handled. We see the neight entry for Node1's IP address is created.

```bash
1857097.663946:          net:netif_receive_skb: dev=eth0 skbaddr=0xffff9e25e838f100x len=28
1857097.663954:          neigh:neigh_create: family 2 dev eth0 entries 18 primary_key4 172.28.0.11 primary_key6 6830::6234:6300:0 created 1 gc_exempt 0
1857097.663960:          neigh:neigh_update: family 2 dev eth0 lladdr 000000000000 flags 00 nud_state 0x0 type 01 dead 0 refcnt 2 primary_key4 172.28.0.11 
1857097.663967:          neigh:neigh_update_done: family 2 dev eth0 lladdr 0242ac1c000b flags 00 nud_state stale type 01 dead 0 refcnt 2 primary_key4 172.28.0.11
```

Then a new packet is queued for transmission on Node3's eth0 interface. This would be the ARP response.

```bash
1857097.663972:           net:net_dev_queue: dev=eth0 skbaddr=0xffff9e25e838ff00x len=42
1857097.663978:           net:net_dev_start_xmit: dev=eth0 queue_mapping=0 skbaddr=0xffff9e25e838ff00 vlan_tagged=0 vlan_proto=0x0000 vlan_tci=0x0000 
1857097.663983:           net:netif_rx_entry: dev=vethf330287 napi_id=0x3 queue_mapping=0 skbaddr=0xffff9e25e838ff00 vlan_tagged=0 vlan_proto=0x0000 
1857097.663988:           net:netif_rx: dev=vethf330287 skbaddr=0xffff9e25e838ff00x len=28
1857097.663992:           net:netif_rx_exit: ret=0
1857097.663997:           net:net_dev_xmit: dev=eth0 skbaddr=0xffff9e25e838ff00 len=42 rc=0
```

We can see again the packet is recieved on the host veth interface, proccessed by the bridge (which updates is FDB for the source MAC address), and then queued for transmission on the veth pair to Node1's eth0 interface.

```bash
1857097.664003:            net:netif_receive_skb: dev=vethf330287 skbaddr=0xffff9e25e838ff00x len=28
1857097.664008:            bridge:br_fdb_update: br_dev br-23bc52c38b4c source vethf330287 addr 02:42:ac:1c:00:0d vid 0 flags 0x0
1857097.664016:            net:net_dev_queue: dev=veth2f068b3 skbaddr=0xffff9e25e838ff00x len=42
1857097.664021:            net:net_dev_start_xmit: dev=veth2f068b3 queue_mapping=0 skbaddr=0xffff9e25e838ff00 vlan_tagged=0 vlan_proto=0x0000 vlan_tci=0x0000 
1857097.664026:            net:netif_rx_entry: dev=eth0 napi_id=0x3 queue_mapping=0 skbaddr=0xffff9e25e838ff00 vlan_tagged=0 vlan_proto=0x0000 
1857097.664031:            net:netif_rx: dev=eth0 skbaddr=0xffff9e25e838ff00x len=28
1857097.664036:            net:netif_rx_exit: ret=0
1857097.664042:            net:net_dev_xmit: dev=veth2f068b3 skbaddr=0xffff9e25e838ff00 len=42 rc=0
```

When the containers eth0 interface recieves the packet, it process the ARP response and updates its neighbor entry for Node3's IP address.

```bash
1857097.664047:            net:netif_receive_skb: dev=eth0 skbaddr=0xffff9e25e838ff00x len=28
1857097.664052:            neigh:neigh_update: family 2 dev eth0 lladdr 000000000000 flags 00 nud_state incomplete type 01 dead 0 refcnt 3 primary_key4 172.28.0.13
```

Finally we can observe a round trip ping, which I will not go into too much detail, but if you followed the above you can probably trace the path of the ICMP echo request and reply packets.

```bash
1857097.664057:      net:net_dev_queue: dev=eth0 skbaddr=0xffff9e25e838e300x len=98
1857097.664062:      net:net_dev_start_xmit: dev=eth0 queue_mapping=0 skbaddr=0xffff9e25e838e300 vlan_tagged=0 vlan_proto=0x0000 vlan_tci=0x0000 
1857097.664067:      net:netif_rx_entry: dev=veth2f068b3 napi_id=0x3 queue_mapping=0 skbaddr=0xffff9e25e838e300 vlan_tagged=0 vlan_proto=0x0000 
1857097.664072:      net:netif_rx: dev=veth2f068b3 skbaddr=0xffff9e25e838e300x len=84
1857097.664077:      net:netif_rx_exit: ret=0
1857097.664082:      net:net_dev_xmit: dev=eth0 skbaddr=0xffff9e25e838e300 len=98 rc=0
1857097.664088:      neigh:neigh_update_done: family 2 dev eth0 lladdr 0242ac1c000d flags 00 nud_state reachable type 01 dead 0 refcnt 3 primary_key4 172.28.
1857097.664093:      net:netif_receive_skb: dev=veth2f068b3 skbaddr=0xffff9e25e838e300x len=84
1857097.664098:      net:net_dev_queue: dev=vethf330287 skbaddr=0xffff9e25e838e300x len=98
1857097.664103:      net:net_dev_start_xmit: dev=vethf330287 queue_mapping=0 skbaddr=0xffff9e25e838e300 vlan_tagged=0 vlan_proto=0x0000 vlan_tci=0x0000 
1857097.664108:      net:netif_rx_entry: dev=eth0 napi_id=0x3 queue_mapping=0 skbaddr=0xffff9e25e838e300 vlan_tagged=0 vlan_proto=0x0000 
1857097.664113:      net:netif_rx: dev=eth0 skbaddr=0xffff9e25e838e300x len=84
1857097.664118:      net:netif_rx_exit: ret=0
1857097.664123:      net:net_dev_xmit: dev=vethf330287 skbaddr=0xffff9e25e838e300 len=98 rc=0
1857097.664128:      net:netif_receive_skb: dev=eth0 skbaddr=0xffff9e25e838e300x len=84
1857097.664144:      neigh:neigh_event_send_done: family 2 dev eth0 lladdr 0242ac1c000b flags 00 nud_state delay type 01 dead 0 refcnt 2 primary_key4 172.28.0.
1857097.664149:      net:net_dev_queue: dev=eth0 skbaddr=0xffff9e25e838ff00x len=98
1857097.664155:      net:net_dev_start_xmit: dev=eth0 queue_mapping=0 skbaddr=0xffff9e25e838ff00 vlan_tagged=0 vlan_proto=0x0000 vlan_tci=0x0000 protocol=0x0>
1857097.664160:      net:netif_rx_entry: dev=vethf330287 napi_id=0x3 queue_mapping=0 skbaddr=0xffff9e25e838ff00 vlan_tagged=0 vlan_proto=0x0000 vlan_tci=>
1857097.664165:      net:netif_rx: dev=vethf330287 skbaddr=0xffff9e25e838ff00x len=84
1857097.664170:      net:netif_rx_exit: ret=0
1857097.664175:      net:net_dev_xmit: dev=eth0 skbaddr=0xffff9e25e838ff00 len=98 rc=0
1857097.664180:      net:netif_receive_skb: dev=vethf330287 skbaddr=0xffff9e25e838ff00x len=84
1857097.664185:      net:net_dev_queue: dev=veth2f068b3 skbaddr=0xffff9e25e838ff00x len=98
1857097.664190:      net:net_dev_start_xmit: dev=veth2f068b3 queue_mapping=0 skbaddr=0xffff9e25e838ff00 vlan_tagged=0 vlan_proto=0x0000 vlan_tci=0x0000 proto>
1857097.664195:      net:netif_rx_entry: dev=eth0 napi_id=0x3 queue_mapping=0 skbaddr=0xffff9e25e838ff00 vlan_tagged=0 vlan_proto=0x0000 vlan_tci=0x0000 >
1857097.664200:      net:netif_rx: dev=eth0 skbaddr=0xffff9e25e838ff00x len=84
1857097.664205:      net:netif_rx_exit: ret=0
1857097.664210:      net:net_dev_xmit: dev=veth2f068b3 skbaddr=0xffff9e25e838ff00 len=98 rc=0
1857097.664215:      net:netif_receive_skb: dev=eth0 skbaddr=0xffff9e25e838ff00x len=84
```

As you can see from the above, even simple container networking involves a host of networking principles and Linux kernel features. From ARP requests and responses to packet queuing and processing, there is much to explore!

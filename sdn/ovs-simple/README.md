# Simple OVS

Below Ill explore a "simple" OVS setup with Docker containers. This is a great way to get started with OVS and understand how it works without the hyperscale complexity. Its also a way to get an idea around why certain features exist in order to implement scale. Where manual programability breaks down and why dynamic programmability is needed. The setup will prograssivly get more complex as we explore the features of OVS and how it can be used to implement network functions.

## Single L2 Domain (simple model)

For the initial setup, we will use the following:   

* A single Ubuntu VM
* Connected via a NAT gateway for internet connectivity (interface enp0s3)
* Connected via a host-only network for private connectivity between the VMs (interface enp0s8)
* The host network will be on 172.16.56.0/24
* The container network will be on 10.244.0.0/16

The network design will start with a single L2 domain. We will start with a simple setup and progressivly add more complexity. We'll talk about where this breaks down and whats required to manage the complexity. 

First create the virtualbox VM using vagrant. (FYI - I like to use VBox because its lightweigh and easy and allows me to keep my host clean from experimental networking changes).

```
$ PROVISIONER=ovs-simple/provision.yml vagrant up node1
...
(success)
vagrant ssh node1
```

On the VM we can see the following 

```
vagrant@node1:~$ ip a show; ip route show
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
    inet6 ::1/128 scope host 
       valid_lft forever preferred_lft forever
2: enp0s3: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc fq_codel state UP group default qlen 1000
    link/ether 02:47:63:8a:6b:31 brd ff:ff:ff:ff:ff:ff
    inet 10.0.2.15/24 metric 100 brd 10.0.2.255 scope global dynamic enp0s3
       valid_lft 84274sec preferred_lft 84274sec
    inet6 fe80::47:63ff:fe8a:6b31/64 scope link 
       valid_lft forever preferred_lft forever
3: enp0s8: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc fq_codel state UP group default qlen 1000
    link/ether 08:00:27:f9:dc:7c brd ff:ff:ff:ff:ff:ff
    inet 172.16.56.2/24 brd 172.16.56.255 scope global enp0s8
       valid_lft forever preferred_lft forever
    inet6 fe80::a00:27ff:fef9:dc7c/64 scope link 
       valid_lft forever preferred_lft forever
4: docker0: <NO-CARRIER,BROADCAST,MULTICAST,UP> mtu 1500 qdisc noqueue state DOWN group default 
    link/ether 02:42:ff:75:fc:3e brd ff:ff:ff:ff:ff:ff
    inet 172.17.0.1/16 brd 172.17.255.255 scope global docker0
       valid_lft forever preferred_lft forever
5: ovs-system: <BROADCAST,MULTICAST> mtu 1500 qdisc noop state DOWN group default qlen 1000
    link/ether 8e:28:18:f3:6d:f4 brd ff:ff:ff:ff:ff:ff
6: br-int: <BROADCAST,MULTICAST> mtu 1500 qdisc noop state DOWN group default qlen 1000
    link/ether be:d1:da:fb:69:48 brd ff:ff:ff:ff:ff:ff

default via 10.0.2.2 dev enp0s3 proto dhcp src 10.0.2.15 metric 100 
10.0.2.0/24 dev enp0s3 proto kernel scope link src 10.0.2.15 metric 100 
10.0.2.2 dev enp0s3 proto dhcp scope link src 10.0.2.15 metric 100 
10.0.2.3 dev enp0s3 proto dhcp scope link src 10.0.2.15 metric 100 
172.16.56.0/24 dev enp0s8 proto kernel scope link src 172.16.56.2 
172.17.0.0/16 dev docker0 proto kernel scope link src 172.17.0.1 linkdown

vagrant@node1:~$ sudo ovs-vsctl show
cf9f17d3-031c-4864-8f55-09d328c134d2
    Bridge br-int
        fail_mode: secure
        datapath_type: system
        Port br-int
            Interface br-int
                type: internal
    ovs_version: "2.17.9"
```
Ill create two containers and connect them as ports to the OVS bridge. Ill use ovs-docker to do this as it simplifies creating vETH pairs and connecting them to the OVS bridge. 

```
vagrant@node1:~$ docker-compose -f shared/docker-compose.yml up -d
Creating netsho2 ... done
Creating netsho1 ... done

vagrant@node1:~$ docker ps
CONTAINER ID   IMAGE               COMMAND            CREATED         STATUS         PORTS     NAMES
63f11f38dad9   nicolaka/netshoot   "sleep infinity"   9 seconds ago   Up 8 seconds             netsho2
43ab91bf3012   nicolaka/netshoot   "sleep infinity"   9 seconds ago   Up 8 seconds             netsho1

vagrant@node1:~$ sudo ovs-docker add-port br-int eth0 netsho1 --ipaddress=10.244.1.3/16 --macaddress="02:00:00:00:01:03"
vagrant@node1:~$ sudo ovs-docker add-port br-int eth0 netsho2 --ipaddress=10.244.1.4/16 --macaddress="02:00:00:00:01:04"

vagrant@node1:~$ docker exec -it netsho1 ip a show
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
    inet6 ::1/128 scope host 
       valid_lft forever preferred_lft forever
10: eth0@if11: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UP group default qlen 1000
    link/ether 02:00:00:00:01:03 brd ff:ff:ff:ff:ff:ff link-netnsid 0
    inet 10.244.1.3/16 scope global eth0
       valid_lft forever preferred_lft forever
    inet6 fe80::3cf0:ccff:fe49:964e/64 scope link 
       valid_lft forever preferred_lft forever

vagrant@node1:~$ docker exec -it netsho1 ip route show
10.244.0.0/16 dev eth0 proto kernel scope link src 10.244.1.3 

vagrant@node1:~$ sudo ovs-vsctl show
cf9f17d3-031c-4864-8f55-09d328c134d2
    Bridge br-int
        fail_mode: secure
        datapath_type: system
        Port b733d057f2d84_l
            Interface b733d057f2d84_l
        Port b4fea899f46b4_l
            Interface b4fea899f46b4_l
        Port br-int
            Interface br-int
                type: internal
    ovs_version: "2.17.9"
```

Now if we ping netsho2 from netsho1 we should see the traffic flow through the OVS bridge. We can also view the flows in the OVS bridge and see how the traffic is being handled along with the FDB entries.

```
vagrant@node1:~$ docker exec -it netsho1 ping -c3 10.244.1.4
PING 10.244.1.4 (10.244.1.4) 56(84) bytes of data.
64 bytes from 10.244.1.4: icmp_seq=1 ttl=64 time=0.690 ms
64 bytes from 10.244.1.4: icmp_seq=2 ttl=64 time=0.104 ms
64 bytes from 10.244.1.4: icmp_seq=3 ttl=64 time=0.149 ms

--- 10.244.1.4 ping statistics ---
3 packets transmitted, 3 received, 0% packet loss, time 2073ms
rtt min/avg/max/mdev = 0.104/0.314/0.690/0.266 ms

vagrant@node1:~$ sudo ovs-appctl dpctl/dump-flows
recirc_id(0),in_port(3),eth(src=02:00:00:00:01:03,dst=02:00:00:00:01:04),eth_type(0x0800),ipv4(frag=no), packets:2, bytes:196, used:2.660s, actions:4
recirc_id(0),in_port(4),eth(src=02:00:00:00:01:04,dst=02:00:00:00:01:03),eth_type(0x0800),ipv4(frag=no), packets:2, bytes:196, used:2.660s, actions:3

vagrant@node1:~$ sudo ovs-appctl fdb/show br-int
 port  VLAN  MAC                Age
    2     0  02:00:00:00:01:03   14
    3     0  02:00:00:00:01:04   13
```

This is all on a single L2 domain. So when the container starts its ping, it sends an ARP request through eth0 where the OVS bridge forwards it to all ports. The netsho2 container receives the ARP request and responds with its MAC address. The OVS bridge then learns the MAC address and adds it to its FDB.

One could continue to add more containers and connect them to the OVS bridge in the same way. This is a simple L2 domain with no routing complexity. But say a single node was not enough. A not-so-great design would be to continue to add nodes under the same L2 domain and communicate to them through a tunneling protocol like VXLAN or GENEVE. This would allow us to create a L2 domain that spans an L3 network as the tunneling protocol will encapsulate the packet with UDP. However:

- IPAM between the 10.244.0.0/16 network would need to be managed across the cluster
- As the cluster grows, the tunnel connections grow.
- As the cluster grows, the broadcast domain grows. This could lead to ARP requests flooding the network across all nodes. The network may encounter collisions and performance issues leading to undesired latency.
- High churn in container lifetime adds management complexity

A better design here would be to segment L2 domains across nodes. Cross node traffic would be handled over the L3 domain (via the underlay network) using routers. The router would then handle the routing between the L2 domains. Any ARP broadcasts not destined for another subnet would be contained within the L2 domain and not flood the entire cluster. This would allow us to scale the cluster without the issues mentioned above because...

- IPAM can be managed locally on each node for the L2 domain.
- As the cluster grows, the broadcast domain stays the same per node.
- Any churn in container lifetime is handled per node only, a more decentralized approach.

With this design, it means we would need to assign each node a static subnet range that pods are created in locally. Then between nodes, we create a logical router that can route between the subnets. Some IP address planning would still be required here. You could imagine a client specifying how many "containers per node" as a requirement. This would then be used to calculate the subnet size and assign a subnet to each node to accomodate. You might also want to obtain the max node count such that the overall subnet size provided can satisfy up to it.

Lets dig into this design and see how we can implement it with OVS/OVN.

## Multiple L2 Domains (scale model)

### OVS/OVN

First we will start by bringing up both nodes and ssh into them from different terminals.

```
$ PROVISIONER=ovs-simple/provision.yml vagrant up node1 node2
....
$ vagrant ssh node1
$ vagrant ssh node2
```

NOTE: At the time of writing this I was new to OVS. I tried for about a week to configure OVS flow rules to complete the following experiment to no avail. So the next best option was to use OVN to do it for me. 

OVN is a logical network virtualization system built on top of OVS. It provides a way to create logical networks to configure flows that reflect the desired network topology. OVN consists of a "NorthBound" database and a "SouthBound" database. The NBDB is configured with logical networking resources of which get translated by Northd to logical flows into the SBDB. 

We will use node1 as the central owner of the NB/SB DB. All other nodes will point to node1 for their OVS flow configurations. The following will be done on node 1 only to configure OVN.

```
vagrant@node1:~$ sudo ovn-nbctl set-connection ptcp:6641
vagrant@node1:~$ sudo ovn-sbctl set-connection ptcp:6642

vagrant@node1:~$ netstat -nltp
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name    
tcp        0      0 0.0.0.0:6642            0.0.0.0:*               LISTEN      -                   
tcp        0      0 0.0.0.0:6641            0.0.0.0:*               LISTEN      -                   
....

```

Next (on each node) we will update the Open_VSwitch database to point to the OVN NB/SB DB. This will allow OVS to use OVN to configure its flows.

```
$ sudo ovs-vsctl set open . external-ids:ovn-remote=tcp:172.16.56.2:6642
$ sudo ovs-vsctl set open . external-ids:ovn-encap-type=geneve
$ sudo ovs-vsctl set open . external-ids:ovn-encap-ip=172.16.56.2
```

Now the fun begins. We can start creating the logical resources that will reflect the network.

```
$ sudo ovn-nbctl lr-add lr0

$ sudo ovn-nbctl ls-add ls-node1
$ sudo ovn-nbctl ls-add ls-node2

# These will become the default gateways for the containers network namespaces.
$ sudo ovn-nbctl lrp-add lr0 lr-node1 00:00:00:01:01:01 10.244.1.1/24
$ sudo ovn-nbctl lrp-add lr0 lr-node2 00:00:00:02:01:01 10.244.2.1/24

$ sudo ovn-nbctl lsp-add ls-node1 ls-node1-lr
$ sudo ovn-nbctl lsp-set-type ls-node1-lr router
$ sudo ovn-nbctl lsp-set-addresses ls-node1-lr router
$ sudo ovn-nbctl lsp-set-options ls-node1-lr router-port=lr-node1

$ sudo ovn-nbctl lsp-add ls-node2 ls-node2-lr
$ sudo ovn-nbctl lsp-set-type ls-node2-lr router
$ sudo ovn-nbctl lsp-set-addresses ls-node2-lr router
$ sudo ovn-nbctl lsp-set-options ls-node2-lr router-port=lr-node2


$ sudo ovn-nbctl show
switch 311cdc08-a7e3-4e5e-81a5-ba2e02c2d658 (ls-node2)
    port ls-node2-lr
        type: router
        router-port: lr-node2
switch 06d2b4af-7e5f-42d2-9692-7b9ad21902ae (ls-node1)
    port ls-node1-lr
        type: router
        router-port: lr-node1
router d8759914-b6d8-4e0c-b8dc-e799d94aea0e (lr0)
    port lr-node2
        mac: "00:00:00:02:01:01"
        networks: ["10.244.2.1/24"]
    port lr-node1
        mac: "00:00:00:01:01:01"
        networks: ["10.244.1.1/24"]
```

Now that we've setup the node logical resources, lets create the containers and connect them to their respective logical switches. Ill do this in a praticular order to demosntrate how the logical flows are created and how the containers can communicate with each other. 

```
$ sudo ovs-docker add-port br-int eth0 netsho1 --ipaddress="10.244.1.3/24" --gateway="10.244.1.1" --macaddress=02:00:00:00:01:03
$ sudo ovs-docker add-port br-int eth0 netsho2 --ipaddress="10.244.1.4/24" --gateway="10.244.1.1" --macaddress=02:00:00:00:01:04
$ sudo ovs-docker add-port br-int eth0 netsho3 --ipaddress="10.244.1.5/24" --gateway="10.244.1.1" --macaddress=02:00:00:00:01:05
$ sudo ovs-docker add-port br-int eth0 nginx1 --ipaddress="10.244.1.6/24" --gateway="10.244.1.1" --macaddress=02:00:00:00:01:06

vagrant@node1:~$ docker exec -it netsho1 ip route show
default via 10.244.1.1 dev eth0 
10.244.1.0/24 dev eth0 proto kernel scope link src 10.244.1.3 
vagrant@node1:~$ docker exec -it netsho1 ip addr show
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
    inet6 ::1/128 scope host 
       valid_lft forever preferred_lft forever
22: eth0@if23: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UP group default qlen 1000
    link/ether 02:00:00:00:01:03 brd ff:ff:ff:ff:ff:ff link-netnsid 0
    inet 10.244.1.3/24 scope global eth0
       valid_lft forever preferred_lft forever
    inet6 fe80::78c6:59ff:fe78:f47/64 scope link 
       valid_lft forever preferred_lft forever

vagrant@node1:~$ sudo ovs-vsctl show
cf9f17d3-031c-4864-8f55-09d328c134d2
    Bridge br-int
        fail_mode: secure
        datapath_type: system
        Port ffd188a9e8fb4_l
            Interface ffd188a9e8fb4_l
        Port d3944e85802b4_l
            Interface d3944e85802b4_l
        Port "098362435df84_l"
            Interface "098362435df84_l"
        Port br-int
            Interface br-int
                type: internal
        Port "360c3394395b4_l"
            Interface "360c3394395b4_l"
    ovs_version: "2.17.9"


```

The contianers and their interfaces are setup and connected to the OVS bridge. However, they cannot communicate with each other yet.

```
$ docker exec -it netsho1 ping -c1 10.244.1.4
PING 10.244.1.4 (10.244.1.4) 56(84) bytes of data.
From 10.244.1.3 icmp_seq=1 Destination Host Unreachable

--- 10.244.1.4 ping statistics ---
1 packets transmitted, 0 received, +1 errors, 100% packet loss, time 0ms

# By default when using OVN, if no flows are configured, the packets will be dropped.

$ sudo ovs-appctl dpctl/dump-flows
recirc_id(0),in_port(2),eth(),eth_type(0x0806), packets:2, bytes:84, used:9.932s, actions:drop
```

This is because we have not configured the logical flows to allow communication between the containers. We can either do that ourselves manually or use OVN. Since we've already started to configure OVN with our logical resources, we will continue to use it to configure our flows.

```
# Flows before adding the logical port for the containers.

vagrant@node1:~$ sudo ovs-ofctl dump-flows br-int
 cookie=0x0, duration=63156.644s, table=37, n_packets=0, n_bytes=0, priority=150,reg10=0x2/0x2 actions=resubmit(,38)
 cookie=0x0, duration=63156.644s, table=37, n_packets=0, n_bytes=0, priority=150,reg10=0x10/0x10 actions=resubmit(,38)
 cookie=0x0, duration=63156.644s, table=37, n_packets=0, n_bytes=0, priority=0 actions=resubmit(,38)
 cookie=0x0, duration=63156.644s, table=39, n_packets=0, n_bytes=0, priority=0 actions=load:0->NXM_NX_REG0[],load:0->NXM_NX_REG1[],load:0->NXM_NX_REG2[],load:0->NXM_NX_REG3[],load:0->NXM_NX_REG4[],load:0->NXM_NX_REG5[],load:0->NXM_NX_REG6[],load:0->NXM_NX_REG7[],load:0->NXM_NX_REG8[],load:0->NXM_NX_REG9[],resubmit(,40)
 cookie=0x0, duration=63156.644s, table=64, n_packets=0, n_bytes=0, priority=0 actions=resubmit(,65)


vagrant@node1:~$ sudo ovn-nbctl lsp-add ls-node1 netsho1
vagrant@node1:~$ sudo ovn-nbctl lsp-set-addresses netsho1 "02:00:00:00:01:03 10.244.1.3"
vagrant@node1:~$ sudo ovn-nbctl lsp-add ls-node1 netsho2
vagrant@node1:~$ sudo ovn-nbctl lsp-set-addresses netsho2 "02:00:00:00:01:04 10.244.1.4"

vagrant@node1:~$ sudo ovn-nbctl show
switch 311cdc08-a7e3-4e5e-81a5-ba2e02c2d658 (ls-node2)
    port ls-node2-lr
        type: router
        router-port: lr-node2
switch 06d2b4af-7e5f-42d2-9692-7b9ad21902ae (ls-node1)
    port netsho2
        addresses: ["02:00:00:00:01:04 10.244.1.4"]
    port ls-node1-lr
        type: router
        router-port: lr-node1
    port netsho1
        addresses: ["02:00:00:00:01:03 10.244.1.3"]
router d8759914-b6d8-4e0c-b8dc-e799d94aea0e (lr0)
    port lr-node2
        mac: "00:00:00:02:01:01"
        networks: ["10.244.2.1/24"]
    port lr-node1
        mac: "00:00:00:01:01:01"
        networks: ["10.244.1.1/24"]

# To complete the logical port configuration, we need to tell our OVS interfaces to use them as the external ID. This will allow the OVS bridge to use the logical ports for the containers and generate the flows.

$ iface=$(sudo ovs-vsctl --bare --columns=name find Interface external_ids:container_id=netsho1)
$ sudo ovs-vsctl set interface $iface external_ids:iface-id=netsho1

$ iface=$(sudo ovs-vsctl --bare --columns=name find Interface external_ids:container_id=netsho2)
$ sudo ovs-vsctl set interface $iface external_ids:iface-id=netsho2

# We we could observe many more flows being created in the OVS bridge.

$ sudo ovs-ofctl dump-flows br-int | wc -l
412

```

Now that we've setup the container logical ports on the OVN logical switch for node1, we should be able to ping between the containers. We can also check the flows for the data path and see how the traffic is being handled. Traffic is being passed to the ovn-controller userspace process which is responsible for managing the logical flows and routing the traffic between the containers. For example the ARP request (dst=ff) between src and dest.

```
vagrant@node1:~$ docker exec -it netsho1 ping -c1 10.244.1.4
PING 10.244.1.4 (10.244.1.4) 56(84) bytes of data.
64 bytes from 10.244.1.4: icmp_seq=1 ttl=64 time=0.510 ms

--- 10.244.1.4 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 0.510/0.510/0.510/0.000 ms

vagrant@node1:~$ sudo ovs-appctl dpctl/dump-flows
recirc_id(0),in_port(2),eth(src=02:00:00:00:01:03,dst=ff:ff:ff:ff:ff:ff),eth_type(0x0806),arp(sip=10.244.1.3,tip=10.244.1.4,op=1/0xff,sha=02:00:00:00:01:03,tha=00:00:00:00:00:00), packets:0, bytes:0, used:never, actions:userspace(pid=4294967295,slow_path(action))
recirc_id(0),in_port(3),eth(src=02:00:00:00:01:04,dst=ff:ff:ff:ff:ff:ff),eth_type(0x0806),arp(sip=10.244.1.4,tip=10.244.1.3,op=1/0xff,sha=02:00:00:00:01:04,tha=00:00:00:00:00:00), packets:0, bytes:0, used:never, actions:userspace(pid=4294967295,slow_path(action))
recirc_id(0),in_port(3),eth(src=02:00:00:00:01:04,dst=02:00:00:00:01:03),eth_type(0x0800),ipv4(frag=no), packets:0, bytes:0, used:never, actions:2
recirc_id(0),in_port(2),eth(src=02:00:00:00:01:03,dst=02:00:00:00:01:04),eth_type(0x0800),ipv4(frag=no), packets:0, bytes:0, used:never, actions:3
```

One interesting observation is the FDB is not populated with the MAC addresses of the containers. This is because OVS does not use the FDB to learn MAC addresses with configured via OVN flows. Instead, it uses the logical ports to route traffic between the containers. The flows are created based on the logical ports and their associated IP addresses. So everything is driven logically via flows provided by the OVN controller ready the SBDB on the node.

```
vagrant@node1:~$ sudo ovs-appctl fdb/show br-int
 port  VLAN  MAC                Age
```

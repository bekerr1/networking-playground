# Software Defined Networking

As cloud computing continues to provide immense value, further abstracting compute via virtualization and containers continue to expand. Thus, the need to program massive fleets of virtual compute grows. A more scalable, simple, and manageable way to tune the networks that connect these fleets arise. This is where software defined networking (SDN) comes into play. Seperation of concerns between the control plane (how the network is defined) and the data plane (how those definitions apply) is key. This seperation natrually leads to an environment where APIs and resources can be applied to the control plane, processed by some central controller, and enacted on by the data plane. This allows for scalable programmability, making tuning massive networks much simpler than working per network entity.

Additionally, container orchastratos like Kubernetes, there continues to be a need to provide advanced virtual networking between workloads as the "host" concept is further abstracted away, to more of a "workload" or "contained process", most of which still have a need to act as a host in the network they preside. The concept of __underlay__ and __overlay__ networks is key to understanding how these workloads can communicate with each other, and how they can be managed at scale.

* Underlay Network: The physical network infrastructure that provides connectivity between devices. This includes routers, switches, and other networking hardware.
* Overlay Network: A virtual network that is built on top of the underlay network. It allows for the creation of logical networks that can span multiple physical networks, providing isolation and flexibility.

## Open vSwitch

Open vSwitch (OVS) is a popular open-source virtual switch project that provides a way to configure the equivalent of a physical switch between VMs and containers in a virtualized way. Additionally, its integration with OpenFlow and SDN controllers like Open Virutal Network (OVN) make it ideal for coordinating complex networking constructs across massive scale. Its important to note that OVS works at lower layers (L2-L4) and doesnt concern itself with application logic (HTTP). As such, there is little user/kernel space traversal which makes operations more efficient (than an L7 proxy like Envoy) at the cost of more advanced tuning. You would expect the following type of tunability at each layer 

### Data Link (L2)

- This is the most common layer that applies to switching (though not exclusive)
- MAC address learning (as seen in the ARP section)
- Bridging network namespaces on a host 
- VLAN tagging

### Network (L3)

- IP routing capabilities (limited)
- Combined with OVN to provide distributed routing 

### Transport (L4)

- Take actions on port numbers (UDP/TCP)
- Access Control, Load balancing, and QoS enforcement

### Flows

In the context of OVS, a flow is a set of packets that match a specific header field and are treated the same by the switch. These flows can be matched against a condition and have some action applied to them.

### Dynamic Programmability

For VMs/Containers at cloud provider scale, dynamic programmability is important to react in real-time to changes, configure fleets, and simplify complex management. Things like OpenFlow and Open Virtual Network (OVN) provide this capability. Ill explore them more below

## Hands On 

For these hands on, Ill start with a simple OVS example with Docker on my host. Then Ill explore OVN-Kubernetes. Being someone with a Kubernetes background, I was interested to dive into OVN-k8s and see how an OVS based CNI differs from your typical calico/weave/flannel setup one becomes familar with after working with k8s for some time.

(Simple OVS)[link]
(OVN-Kubernetes)[link]

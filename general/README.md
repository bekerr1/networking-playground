# General Concepts

The following are some general networking concepts that apply to the repo. I work on Linux/Unix systems so everything will be based on that.

## OSI Model

Packets can flow in and out of members of a network in many different ways, but generally the flow is based off of a shared layer based model, known as the OSI model. Some layers and protocols are more popular and applicable to how value is generated in todays world, but the general layout is the following.

```
+-------------------+
| 7. Application    | <-- Data/message based |
+-------------------+                        |
| 6. Presentation   | <-- Data/message based | <-- User Space Applications
+-------------------+                        |
| 5. Session        | <-- Data/message based |
+-------------------+ ---- Kernel/User space boundary (via sockets)
| 4. Transport      | <-- Segment/Datagram based (TCP/UDP)
+-------------------+
| 3. Network        | <-- Packet based (IP/UDP)
+-------------------+
| 2. Data Link      | <-- Frame based (Ethernet)
+-------------------+ ---- Device boundary (via drivers)
| 1. Physical       | <-- Bit based (Device Drivers)
+-------------------+
```

Implementing networks this way has shown to be worth it and has proven itself time and again.

## Types of Participants in a Network 

Depending on the role designated to the entity in the network, it could have more/less responsibility. For example you could image a scenario where a VM is running on a baremetal host. The VM runs some set of applications that communicate to other similar VMs in the same or different networks. And depdning on whether the data is from within the network vs external, it will take/interact with different pathways and entities. This is where you might encounter concepts like *broadcast domains* and *collision domains*. Within a local network (LAN), you might have VMs connected to switches/bridges that associate entities locally. These switches/bridges may increase the broadcast domain for those particiapnts. Between networks, you may introduce something like a router that serves as a gateway. The router segments broadcast domains such that any packets broadcasted on the local network are dropped. Data that reaches such entities may never make it to user space for lack of necessity. This may also improve performance.

Entities within a network over time tend to gradually learn their place and others which also improves performance. But in an everchanging world where microservices and distributed systems provide a unique value add to large enterprises, the network needs to react to dynamic changes efficiently.

Participants:

* VM/Application - Usually some sort of endpoint. Serves a purpose other than purley providing for the network 
* Switch/Bridge - Connects endpoints in a local network. Increases a single broadcast domain while lessening the collision domain. Might only serve L2 but could be exteded to L3.
* Routers - Connects networks / Broadcast domains. Usually serves at L3 to connect subnets/networks.
* Repeater (Deprecated) - Used to be used to relay messages from the incoming port to all outgoing ports. Very dumb machines.

## Data Flows

### Transmission (TX)

A very common workflow to demonstrate might be an HTTP request. This request would adhere to the client/server model. As such, an application would have some endpoint and URI to send the request to. It would format some data at application layer to provide to the server. We will start with an empty payload and append to it as we traverse down the stack.

```
+-------------------+
| 7. HTTP            | []
+-------------------+
```

Lets say we are sending a POST request to the server for /foo at http://managment.bar.com. Since we are using HTTP, we would format the data as per that protocol. The data then becomes

```
+-------------------+
| 7. HTTP           | [HTTP Header | Payload (body)]
+-------------------+
```

The header and body might be something like...

```
POST /foo HTTP/1.1
Host: mgmt.bar.com
Content-Type: application/json
Content-Length: 18

{
  "hello": "world"
}
```

The HTTP client implementation would seek to establish a connection with the server by first creating a TCP socket using system calls. System calls are just APIs for the kernel that user space applications can leverage. HTTP is most commonly implemented over TCP because of its stateful and reliable communication methods. The set of system calls may look something like 

```
socket(AF_INET, SOCK_STREAM, IPPROTO_IP) = 3 <-- create a TCP socket over IP. Socket FD is '3'
getaddrinfo("mgmt.bar.com", "443", {ai_family=AF_INET, ai_socktype=SOCK_STREAM}, 0x7fff...) = 0
connect(3, {sa_family=AF_INET, sin_port=htons(443), sin_addr=inet_addr("93.184.216.34")}, 16) = 0 <-- run 'connect' against the socket FD with addr info
fcntl(3, F_GETFL)                       = 0x2 (flags O_RDWR)
fcntl(3, F_SETFL, O_RDWR|O_NONBLOCK)    = 0
setsockopt(3, SOL_SOCKET, SO_KEEPALIVE, [1], 4) = 0 <-- optionally configure the socket
write(3, "POST /foo HTTP/1.1\r\nHost: mgmt.bar.com\r\nContent-Type: application/json\r\nContent-Length: 18\r\n\r\n{\"hello\": \"world\"}", 77) = 77 <--- write content to the socket
read(3, 0x7fff..., 1024)               = 512 <-- Read any response
close(3) <-- Close the socket
```

Upon updating our data illustration for the 'socket', 'getaddrinfo' and 'connect' syscalls, we might get something like so making its way down the stack

```
+-------------------+
| 7. HTTP           | [HTTP Header (VERB / URI / Content-Type) | Payload (body)]
+-------------------+
| 4. TCP            | [TCP Header (Source port / Dest port) | Payload ([HTTP Header | Payload (body)]) ]
+-------------------+
| 3. IPv4           | [IPv4 Header (Source IP / Dest IP) | Payload ([TCP Header (Source port / Dest port) | Payload ([HTTP Header | Payload (body)]) ]) ]
+-------------------+
```

Now the real fun begins! The kernel will start processing the request down each layer. It would build up the payload layer by layer, ensuring that as it traverses down, when the payload reaches the destination, it would be able to unwind and deliver the message successfully and in a commonly shared manner (via shared protocol agreements). Since our request is using IPv4, the subsystem would try to resolve this IP address to neighbor system within the network. If non is found, IPv4 leverages ARP to resolve this (roughly equivalent to how DNS resolves hostnames to IP addresses). Feel free to review the [ARP section](https://github.com/bekerr1/networking-playground/tree/main/arp) in this repo for a full breakdown (that includes an interesting journey into Linux tracepoints). In short, an ARP "who-has" request will be broadcast to the network. Eventually (if the network is configured correctly), someone will respond with "is-at" with the neighbor system MAC address. The neigh subsystem will cache this entry with the primary key being the IPv4 address and the status (reachable). We can update our payload to reflect what our data might look like.

```
+-------------------+
| 7. HTTP           | [HTTP Header (VERB / URI / Content-Type) | Payload (body)]
+-------------------+
| 4. TCP            | [TCP Header (Source port / Dest port) | Payload ([HTTP Header | Payload (body)]) ]
+-------------------+
| 3. IPv4           | [IPv4 Header (Source IP / Dest IP) | Payload ([TCP Header (Source port / Dest port) | Payload ([HTTP Header | Payload (body)]) ]) ]
+-------------------+
| 2. Ethernet       | [Eth Header (Source MAC / Dest MAC) | Payload ([IPv4 Header (Source IP / Dest IP) | Payload ([TCP Header (Source port / Dest port) | Payload ([HTTP Header | Payload (body)]) ]) ]) ]
+-------------------+
```

Once all the upper layers have been filled out against the skbuf, its passed to a per-cpu xmit queue (net_dev_xmit). Device drivers implement kernel hooks to dequeue skb's from this queue for transmission.

### Network Traversal

Depending on where the server exists relative to the client, the bits transimtted between each network participant may travel various routes, "hopping" between nodes. Typically, the packet will traverse through the gateway for the local network the client VM exists in. A series of routers may be involved. One would expect protocols like BGP to be involved in the WAN to allow for regional/contenintal routing.

### Reception (RX)

Continuing with the HTTP example, the host the server is running on has now recieved the bits at L1. Meaning the interface recieve (rx) queue contains the bits. In the same why the driver code has hooks to tx the skbuf to bits for trasmission, the driver implementer would hook into rx hooks to provide the kernel ways to dequeue the bits into an skbuf for reception and processing. The kernel implements method to detect rx by interrupts (softirp) or NAPI (an improvement on raw inturrupts), but I wont go too far into this.

This would roughly be the skbuf state for our payload.

```
+-------------------+
| 7. HTTP           | [HTTP Header (VERB / URI / Content-Type) | Payload (body)]
+-------------------+
| 4. TCP            | [TCP Header (Source port / Dest port) | Payload ([HTTP Header | Payload (body)]) ]
+-------------------+
| 3. IPv4           | [IPv4 Header (Source IP / Dest IP) | Payload ([TCP Header (Source port / Dest port) | Payload ([HTTP Header | Payload (body)]) ]) ]
+-------------------+
| 2. Ethernet       | [Eth Header (Source MAC / Dest MAC) | Payload ([IPv4 Header (Source IP / Dest IP) | Payload ([TCP Header (Source port / Dest port) | Payload ([HTTP Header | Payload (body)]) ]) ]) ]
+-------------------+
```

From the above, the kernel would be able to deliver the payload to the right interface (identified by its hardware MAC address). It traverses the network (routers) to end up to the right place using the IPv4 address. A stateful connection is established with error handling and reliable delivery via TCP. Finally, the kernel passes the TCP payload to the destination port of which the application is listening on (via its own socket). Because its an HTTP server, it know how to unpack the data in the TCP payload and interpret everything. Probably, the server has implemented some sort of muxer such that the request would be handled at the /URI level. Application would then react to the header, verb, and HTTP body.

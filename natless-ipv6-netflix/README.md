# Nat-less IPv4/IPv6

Few months ago a stumbled on a youtube video where some Netflix SWEs detailed a novel approach to IPv4/IPv6 translation that involved some Linux kernel capabilities. I thought the talk was interesting and wanted to take a shot at implementing the details and talk about the approach as a "weekend project".

## Premise

Say you own an application and you want to migrate to an IPv6 stack. You might own your application env, but not other services you interact with. These other services may have the same aspirations but are under the same constraints and so on. So what are your options?

* Dual Stack - Defeats the purpose. IPv4 dependency still exists. You will have to wait for all dependencies down the stack to migrate before you can compeltely remove IPv4. This may never come.
* IPv6/IPv4 NAT - Valid approach but costly in terms of monitary and compute resources. Cloud providers would likely charge. Additionally, connection tracking needs to happen per-packet due to NAT.
* eBPF - Less discussed approach but probably valid also and quite cheap. Kernel BPF program can be minimally fed/injected via BPF maps from userspace. So if the seccomp approach is userspace based, eBPF might be considered a kernel space solution. I might try to explore this as a comparison. Downside here is eBPF expertise and ability to maintain is probably slim between the average SWE, though growing. Netflix chose their approach because they had expertise on their team around the seccomp changes (via the original author of the add FD functionality, very convinient), which ofcourse should always be factored in when making design decisions.

## Netflix Approach

The basic summary of the approach is as follows. Build a node agent that hooks into capabilities built into seccomp, allowing it to be notified of system calls ('connect' in this case). From here, determine if there is a route to the IPv4 destination. In other words, determine if its worth it to intervene. If so, run 'connect' from an IPv4 network, aptly named a "translation network". After the connect call succeeds, swap the socket FD from the IPv4 call with the IPv6 call. Meaning the IPv6 application would use the FD from the IPv4 connect call, bypassing all NATing requirements.

## Repro Approach 

Ill be minimally attempting to reproduce this by 

* Developing a 'seccomp-agent' - This agent will be responsible for handling seccomp notify events. Ill have it run on the host, but it could easily be containerized.
* Deploying IPv6 / IPv4 test containers - These containers will be configured to enable seccomp and use a custom seccomp-profile. They will be used to excersize the notify capabilities, call the connect syscalls and test the target functionality. Note the container runtime must have the ability to configure custom seccomp filters via the profiles such that the SCMP_ACT_NOTIFY action takes effect. Ill use containerd which internally uses runc. Ill also explore runc's implementation of seccomp profiles to enable notify.

### Dev Setup and Considerations

Initially I started to explore using KinD and doing everything within k8s but soon realized deploying heterogeneous network stacks (IPv4/IPv6) would be troublesome. Therefore I decided to just use simple container setups using ctr so that I can create/manage my own network namespaces and associate the containers with them.

My custom seccomp profile is as follows and will be provided as a flag when running the container. Its configured to ALLOW by default and for 'connect' syscalls, should NOTIFY.

```json
{
  "defaultAction": "SCMP_ACT_ALLOW",
  "listenerPath": "/run/seccomp-agent.socket",
  "syscalls": [
    {
      "names": [
        "connect"
      ],
      "action": "SCMP_ACT_NOTIFY"
    }
  ]
}
```
Seccomp notificiation events are handled in coordination with the OCI runtime and the Linux Kernel. The test containers use containerd which uses runc by default. Ill reference OSS runc code for handling seccomp notify events below so as to build an understanding of the overall process.

### Exploring runc

The first bits we'll touch on are from (runc's patch bpf code)[https://github.com/opencontainers/runc/blob/main/libcontainer/seccomp/patchbpf/enosys_linux.go#L682]. This logic implements some of whats explained (here)[https://www.kernel.org/doc/html/v5.0/userspace-api/seccomp_filter.html]. Briefly...

```
Seccomp filtering provides a means for a process to specify a filter for incoming system calls. The filter is expressed as a Berkeley Packet Filter (BPF) program, as with socket filters, except that the data operated on is related to the system call being made: system call number and the system call arguments. This allows for expressive filtering of system calls using a filter program language with a long history of being exposed to userland and a straightforward data set
```
And further down in that same doc, (userspace notifications)[https://www.kernel.org/doc/html/v5.0/userspace-api/seccomp_filter.html#userspace-notification] are explained. The following also applies...
```
To acquire a notification FD, use the SECCOMP_FILTER_FLAG_NEW_LISTENER argument to the seccomp() syscall:

fd = seccomp(SECCOMP_SET_MODE_FILTER, SECCOMP_FILTER_FLAG_NEW_LISTENER, &prog);

which (on success) will return a listener fd for the filter, which can then be passed around via SCM_RIGHTS or similar. Note that filter fds correspond to a particular filter, and not a particular task. So if this task then forks, notifications from both tasks will appear on the same filter fd. Reads and writes to/from a filter fd are also synchronized, so a filter fd can safely have many readers.
```
We can observe in the (runc code)[https://github.com/opencontainers/runc/blob/89c46a9496852cbbd53ef6430894c8cf1895b868/libcontainer/seccomp/patchbpf/enosys_linux.go#L674] that this flag is applied via bitwise OR when a set of syscalls fall under the "Notify" action. Later, when the BPF filter/program is loaded, the setting is (queried for)[https://github.com/opencontainers/runc/blob/89c46a9496852cbbd53ef6430894c8cf1895b868/libcontainer/seccomp/patchbpf/enosys_linux.go#L697] to determine the FD to listen on for seccomp notifications. This FD gets passed all the way back up the stack to the '(Init)[https://github.com/opencontainers/runc/blob/main/libcontainer/standard_init_linux.go#L231]' method of the container instance. The FD is then (passed to the parent calling process via a pipe)[https://github.com/opencontainers/runc/blob/main/libcontainer/init_linux.go#L454].

Runc uses a set of constants for syncornization control between the parent and child process, explained a bit (here)[https://github.com/opencontainers/runc/blob/main/libcontainer/sync.go#L18]. In the parent process code, we can observe how these constants are handled (here)[https://github.com/opencontainers/runc/blob/main/libcontainer/process_linux.go#L276]. The one we are particularly interested in is the '(procSeccomp)[https://github.com/opencontainers/runc/blob/main/libcontainer/process_linux.go#L296]' constant. Here we can see the parent essentially retrives the FD, responds to the child as its waiting for a response, then sends the FD and the OCI state to the listening UDS path using (SCM Rights)[https://github.com/opencontainers/runc/blob/main/libcontainer/utils/cmsg.go#L128].

```

			seccompFd, err := pidGetFd(p.pid(), srcFd)
			if err != nil {
				return fmt.Errorf("sync %q get fd %d from child failed: %w", sync.Type, srcFd, err)
			}
			defer seccompFd.Close()
			// We have a copy, the child can keep working. We don't need to
			// wait for the seccomp notify listener to get the fd before we
			// permit the child to continue because the child will happily wait
			// for the listener if it hits SCMP_ACT_NOTIFY.
			if err := writeSync(p.comm.syncSockParent, procSeccompDone); err != nil {
				return err
			}

			bundle, annotations := utils.Annotations(p.config.Config.Labels)
			containerProcessState := &specs.ContainerProcessState{
				Version:  specs.Version,
				Fds:      []string{specs.SeccompFdName},
				Pid:      p.cmd.Process.Pid,
				Metadata: p.config.Config.Seccomp.ListenerMetadata,
				State: specs.State{
					Version:     specs.Version,
					ID:          p.config.ContainerID,
					Status:      specs.StateRunning,
					Pid:         p.initProcessPid,
					Bundle:      bundle,
					Annotations: annotations,
				},
			}
			if err := sendContainerProcessState(p.config.Config.Seccomp.ListenerPath,
				containerProcessState, seccompFd); err != nil {
				return err
			}
```
It only ends up sending the (single FD)[https://github.com/opencontainers/runc/blob/main/libcontainer/utils/cmsg.go#L129], so we can keep that in mind when we go over our agent implementaion. Basically, our agent will want to Recv the SCM Rights message, parse out the notify FD and the included OCI state data, then Accept connections on the notify FD for syscall notifications.

Going through the above was crucial for me to build a full picture of how the container runtime coordinates with linux on this feature. Its good to understand where things are happening, what dependencies are in play, and what is vitally needed (runc / containerd / linux).

### Seccomp Agent - Notification Event Handling

Now that we've set a baseline for how things will be delivered to us, we can start implementing the initial retrival of notification events. Ill try to reference the docs/man pages I use to paint a full picture of my thought/learning process. To start, we need to create a UDS and listen on it. Our agent will use it to recieve IPC from the runc parent process, which recieves from the various child processes via the exec pipe (detailed above).

We'll create a UNIX based SOCK_STREAM socket and provide protocol '0'. From 'man socket'...

```
Name         Purpose                                    Man page
AF_UNIX      Local communication                        unix(7)

SOCK_STREAM     Provides sequenced, reliable, two-way, connection-based byte streams.  An out-of-band data transmission mechanism may be supported.

Normally only a single protocol exists to support a particular socket type within a given protocol  family,  in  which case protocol can be specified as 0
```

```
listener, err := unix.Socket(unix.AF_UNIX, unix.SOCK_STREAM, 0)
if err != nil {
	log.Fatalf("Socket creation error: %v", err)
}
addr := &unix.SockaddrUnix{Name: socketPath}
if err := unix.Bind(listener, addr); err != nil {
	log.Fatalf("Socket bind error: %v", err)
}
```
We will then call 'Listen' and wait for connections via 'Accept'. One interesting aspect of this implementation is what we should define as the 'backlog' parameter. From 'man listen'...

```
The  backlog  argument  defines  the maximum length to which the queue of pending connections for sockfd may grow.  If a connection request arrives when the queue is full, the client may receive an error with an indication of ECONNREFUSED or, if the underlying protocol supports retransmission, the request  may be ignored so that a later reattempt at connection succeeds.
```
We are developing this agent to work in a container env where we could expect to see rapid churn of workloads. In developing platform components, we wouldnt want to disrupt any application clients working within our environment. Since runc will send the notification FD for every conatiner starting, it would not be good if we missed this event or even cause the container to crash. For now Ill just set this to 5, and we will plan to handle all notifications in their own Go routines. We could later do some scale testing to see how rapid scale up of containers with seccomp notify profiles impacts and is impacted by our agent impl.

```
if err := unix.Listen(listener, 5); err != nil {
	log.Fatalf("Socket listen error: %v", err)
}
defer unix.Close(listener)

for {
	fd, _, err := unix.Accept(listener)
	if err != nil {
		log.Printf("Accept error: %v", err)
		continue
	}
	go streamFDHandler(fd)
}

```

From 'man accept'...

```
The  accept() system call is used with connection-based socket types (SOCK_STREAM, SOCK_SEQPACKET).  It extracts the first connection request on the queue of pending connections for the listening socket, sockfd, creates a new connected socket, and returns a new file descriptor referring to that socket.  The newly  created  socket is not in the listening state.  The original socket sockfd is unaffected by this call.
```

In handling the newly extracted FD returned from the 'accept' connection queue, we pass that asyncronously to a handler. The secondary FD handler will...

* Parse our the NotifyFD and the OCI state data from the message as an SCM_RIGHTS message.
* Recieve notifications against the NotifyFD in a polling loop
* Handle notifications for syscall(s). In our case, its only 'connect' for now. As we implement more functionality we may broaden this.

Parsing the NotifyFD from the SCM_RIGHTS message is pretty straight forward.

```
// recvSCMRightsToScmpFD recieves SCM_RIGHTS on the FD passed in and extracts an ScmpFd.
func recvSCMRightsToScmpFD(fd int) (libseccomp.ScmpFd, []byte, error) {
	// We only expect one file descriptor. UnixRights pins FD size to 4 bytes.
	// (https://cs.opensource.google/go/x/sys/+/refs/tags/v0.35.0:unix/sockcmsg_unix.go;l=78)
	oob := make([]byte, unix.CmsgSpace(4))
	stateData := make([]byte, math.MaxInt16)
	n, oobn, _, _, err := unix.Recvmsg(fd, stateData, oob, 0)
	if err != nil {
		log.Printf("Recvmsg error: %v", err)
		return 0, nil, err
	}
	msgs, err := syscall.ParseSocketControlMessage(oob[:oobn])
	if err != nil {
		return 0, nil, fmt.Errorf("ParseSocketControlMessage error: %v", err)
	}
	if len(msgs) == 0 {
		return 0, nil, fmt.Errorf("no SCM_RIGHTS message")
	}
	fds, err := syscall.ParseUnixRights(&msgs[0])
	if err != nil {
		return 0, nil, fmt.Errorf("ParseUnixRights error: %v", err)
	}
	if len(fds) == 0 {
		return 0, nil, fmt.Errorf("no FDs received from SCM_RIGHTS when expected")
	}
	return libseccomp.ScmpFd(fds[0]), stateData[:n], nil
}
```
The above is pretty standard and doesnt really require more explanation. But the next bits will. Querying man pages reveals...

```
$ man -k seccomp_notify
seccomp_notify_alloc (3) - Manage seccomp notifications
seccomp_notify_fd (3) - Manage seccomp notifications
seccomp_notify_free (3) - Manage seccomp notifications
seccomp_notify_id_valid (3) - Manage seccomp notifications
seccomp_notify_receive (3) - Manage seccomp notifications
seccomp_notify_respond (3) - Manage seccomp notifications
```

And looking at 'man seccomp_notify_fd', there is some good high level info on the various notify operations, but nothing too deep. I did notice a message in the notes that lead to some discovery...

```
A complete example of how to avoid these two races is available in the Linux Kernel source tree at /samples/seccomp/user-trap.c.
```

So navigating to (this file)[https://github.com/torvalds/linux/blob/37816488247ddddbc3de113c78c83572274b1e2e/samples/seccomp/user-trap.c#L26], I was able to grok a good starting point for recieving notification, doing some proper error/handling, reading process memory to parse the syscall args and responding appropriatly. Ill touch on some of these aspects in the C code then detail what my Go implementation looks like. Spoiler, it will be very similar!

First we notice the notifications are being handled (syncronously in a while loop)[https://github.com/torvalds/linux/blob/37816488247ddddbc3de113c78c83572274b1e2e/samples/seccomp/user-trap.c#L311]. Ill do the same in my Go program. Next as far as request handling...

* Some light (validation to start)[https://github.com/torvalds/linux/blob/37816488247ddddbc3de113c78c83572274b1e2e/samples/seccomp/user-trap.c#L118]. Ensure the syscall we are handling, which should be 'connect'. We also really only care about IPv4 family SA addr types since the whole goal is to handle IPv4 addresses without NAT. We can also (prepare the response)[https://github.com/torvalds/linux/blob/37816488247ddddbc3de113c78c83572274b1e2e/samples/seccomp/user-trap.c#L118] ahead of time similar to the C code.
* Reading the (process memory to get the syscall args)[https://github.com/torvalds/linux/blob/37816488247ddddbc3de113c78c83572274b1e2e/samples/seccomp/user-trap.c#L131] by opening the /proc/<pid>/mem file. Note, there is an interesting class of edge cases that need to be handled _after_ we've opened the process mem file. The process could exit and a new one spawn with the same PID. We must (validate the notify PID is still valid by ID)[https://github.com/torvalds/linux/blob/37816488247ddddbc3de113c78c83572274b1e2e/samples/seccomp/user-trap.c#L149].

In this example code the point was to detail how you would intercept a mount call. Since we are looking to do something else Ill ignore the rest of this and continue detailing the agent implementation. Heres how Ill apply what has been learned so far 

After parsing SCM rights we can start a poll to recieve notify events. Ive created a handler to take care of this. The resp will be configured depending on the outcome.
```
	for {
		resp, err := handler.RecieveAndHandle()
		if err != nil {
			log.Printf("recieve or handle error: %v", err)
			continue
		}
		if err := libseccomp.NotifRespond(handler.notifyFd, &resp); err != nil {
			log.Printf("NotifRespond error: %v", err)
			continue
		}
	}
```

The handler simply recieves an Scmp Request and passes it along.
```
 func (h *scmpHandler) RecieveAndHandle() (libseccomp.ScmpNotifResp, error) {
	req, err := libseccomp.NotifReceive(h.notifyFd)
	if err != nil {
		return libseccomp.ScmpNotifResp{}, fmt.Errorf("notif recieve error: %v", err)
	}
	log.Printf("Received syscall request")
	return h.handleSyscall(req), nil
}
```

Next we premtivly build a response such that any errors encoutered can provide some "default" return response. I also like passing the response around so all logic can update it in reaction to error/success states. We can parse the syscall name and ensure we are handling the expected syscall. This could catch a case where multiple team members are tasked with handling different syscall or there is a change to the expected set we 'notify' on in our custom profile.
```
func (h *scmpHandler) handleSyscall(req *libseccomp.ScmpNotifReq) libseccomp.ScmpNotifResp {
	// By default, we will not permit any request we error handling.
	resp := libseccomp.ScmpNotifResp{
		ID:    req.ID,
		Error: int32(syscall.EPERM),
		Val:   0,
	}
	syscallName, err := req.Data.Syscall.GetName()
	if err != nil {
		log.Printf("error getting syscall name: %v", err)
		return resp
	}
	switch syscallName {
	case "connect":
		log.Printf("Handling connect syscall for PID %d", req.Pid)
		resp = h.handleConnect(req, resp)
	default:
		log.Printf("recieved a syscall other than 'connect': %s", syscallName)
	}
	return resp
}

```
The following is reading the remote process memory for the connect call. This is similar to what we saw in the example code. It diverges in we need to read the size of the socket addr struct which would be different for IPv4 vs IPv6 due to address size. The request holds the size which we rely on when reading into our buffer.

```
func readConnectRemoteMemory(req *libseccomp.ScmpNotifReq, notifyFd libseccomp.ScmpFd) ([]byte, error) {
	memPath := fmt.Sprintf("/proc/%d/mem", req.Pid)
	file, err := os.Open(memPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open mem file: %w", err)
	}
	defer file.Close()
	log.Println("Args: ", req.Data.Args)
	log.Printf("seeking to %v and reading %v from %v",
		req.Data.Args[1], req.Data.Args[2], memPath)

	// Ensure we handle this TOCTOU edge case.
	if err := libseccomp.NotifIDValid(notifyFd, req.ID); err != nil {
		return nil, fmt.Errorf("notify FD no longer valid for process: %v", err)
	}

	// Seek to the address in memory where the sockaddr is stored.
	if _, err := file.Seek(int64(req.Data.Args[1]), 0); err != nil {
		return nil, fmt.Errorf("failed to seek: %w", err)
	}

	buf := make([]byte, req.Data.Args[2])
	n, err := file.Read(buf)
	if err != nil {
		return nil, fmt.Errorf("failed to read: %w", err)
	}
	if n != int(req.Data.Args[2]) {
		return nil, fmt.Errorf("inaccurate read: read %v bytes instead of %v",
			n, req.Data.Args[2])
	}
	return buf, nil
}
```
These bits detail our objective above. We parse the socket addr buffer into a generic type where we can look at the family. Depending on the family we can further parse the address, ensuring we use structs with correclty sized fields so no data is lost. If the container network matches the socket type, we configure the response to allow the syscall and return. If the container stack differs from the request, we should continue to attempt to handle. Next, if the addr is IPv4 type, we should ensure that there is an IPv4 route for the address such that our connect call would handle the requst. Ive stubbed both of these methods to return false and true respectivly for simplicity. If all conditions are met, we will execute the 'addFD' method. This will handle multiple things.
```
	rsa := parseSockaddr(buf)
	if containerNetworkMatchesSocketType() {
		log.Printf("Container can handle connect as is")
		resp.Error = 0
		resp.Flags = 0
		return resp
	}
	switch rsa.Addr.Family {
	case unix.AF_INET:
		sa := (*unix.RawSockaddrInet4)(unsafe.Pointer(rsa))
		log.Printf("Socker addr of type: %v, IP/Port: %v:%v\n", sa, net.IP(sa.Addr[:]), int(sa.Port>>8|sa.Port<<8))
		if !hostHasIPv4Route() {
			log.Printf("Container has an IPv6 stack. Host has no route for ipv4 addr; no way to handle.")
			resp.Error = int32(unix.EHOSTUNREACH)
			return resp
		}
		log.Printf("Received a valid IPv4 address on an IPv6 network. Attempting ADD_FD from translation net NS")
		fd, err := h.addFD(req, sa)
		if err != nil {
			log.Printf("Error creating IPv4 socket: %v", err)
			return resp
		}
		log.Printf("Connect translation successful. New FD: %v", fd)
		resp.Error = 0
		resp.Val = 0
		resp.Flags = 0
	case unix.AF_INET6:
		sa := (*unix.RawSockaddrInet6)(unsafe.Pointer(rsa))
		log.Printf("Socker addr of type: %v, IP: %v\n", sa, net.IP(sa.Addr[:]))
	}
	return resp
```

The first part of addFD is to enter into a 'translation' netNS. This is simply a preconfigured container with an IPv4 network stack. We will use it to run 'connect' in. Note that it doesnt have the seccomp notify profile applied to it so its connect call doesnt interact with our agent. We also save our home net NS FD so we can re-enter our original net ns after the work is done in the translation network. For my demo this will just be the host namespace but you could imagine maybe the agent existing in its own namespace and needing to navigate back to it.
```
	orig, err := os.Open("/proc/self/ns/net")
	if err != nil {
		return -1, fmt.Errorf("error opening self ns: %w", err)
	}
	defer orig.Close()
	if str := os.Getenv("TRANSLATION_PID"); str != "" {
		translationPID, err = strconv.Atoi(str)
		if err != nil {
			return -1, fmt.Errorf("error parsing TRANSLATION_PID to int: %w", err)
		}
	} else {
		return -1, fmt.Errorf("TRANSLATION_PID environment variable not set")
	}
	err = enterNetNS(translationPID)
	if err != nil {
		return -1, fmt.Errorf("error entering translation net NS: %w", err)
	}
	defer func() {
		unix.Setns(int(orig.Fd()), unix.CLONE_NEWNET)
	}()
```
Next we create/configure a TCP/IP socket and call connect on it. Right now we are assuming TCP/IP as quite common and easiest to deal with. It might be interesting to try for ICMP to handle ping or UDP to handle DNS.
```
	// Now we are in the translation netns. We can create an IPv4 socket to obtain its FD.
	ipv4Fd, err := unix.Socket(unix.AF_INET, unix.SOCK_STREAM, unix.IPPROTO_TCP)
	if err != nil {
		return -1, fmt.Errorf("error creating IPv4 socket in translation net NS: %w", err)
	}
	defer unix.Close(ipv4Fd)

	// sockaddr_in equivalent
	ssa := syscall.SockaddrInet4{Port: int(sa.Port>>8 | sa.Port<<8)}
	copy(ssa.Addr[:], net.IP(sa.Addr[:]))

	// Perform connect() system call
	log.Println("attempting connect at: ", ssa)
	if err := syscall.Connect(ipv4Fd, &ssa); err != nil {
		return -1, fmt.Errorf("error connecting to IPv4 socket: %w", err)
	}
```

Finally we execute the ADD_FD functionality. Ill have to talk about this quite a bit here.

First, youve already noticed Im implementing all this in Go. The default (libseccomp API)[https://github.com/seccomp/libseccomp/tree/main] that further provides C bindings for the Go library currently doesnt have the notify_addfd code. There is a (PR)[https://github.com/seccomp/libseccomp/pull/454] that will be included in the (v2.7.0)[https://github.com/seccomp/libseccomp/milestone/17] release.

To get around this my first instict was to pull the PR and build a custom pkg-config to load from. Then I could access the changes in the PR to make the API calls. The ioctl Go interface is a bit rough in how I would have to define the magic and IOW/IOR vars. Another approach might be to just download kernel headers that include the changes I want and include them via Go bindings. Then I could pass them and call ioctl within the imported C code which, while inconvinient, still seems easier than the pure Go approach. If anyone ends up reading this, just assume Ive done one of these things.

So from the below, we create a NotifAddFD struct and provide the Scmp Request ID. Including the SetFD flag ensures the NewFD is used. We set the NewFD to the FD in the original connect call. When we do this, the SrcFD (say 10) added to the process socket table will be "swaped" with the existing FD in the NewFD field (say 4). Another way to explain this is, if our agent gets a connect call that uses socket FD '5'. We create a socket and call 'connect' in a different net NS with FD '10'. When we call add FD on '10', it will be added to the original 'connect' process, the original FD of '5' is closed, and the FD that would have been '10' assumes the value of '5'. 
```
	add := libseccomp.NotifAddFD{
		ID:         req.ID,
		Flags:      libseccomp.AddfdFlagSetFD,
		SrcFD:      ipv4Fd,
		NewFD:      int(req.Data.Args[0]),
		NewFDFlags: unix.O_CLOEXEC,
	}
	addedFd, err := libseccomp.NotifyAddFD(int(h.notifyFd), add)
	if err != nil {
		log.Printf("NotifyAddFD error: %v\n", err)
		return -1, err
	}
	return addedFd, nil
}
```

Last, we set the resp fields to indicate success and return it.
```
		resp.Error = 0
		resp.Val = 0
		resp.Flags = 0
        ....
	}
	return resp
```

### Demo

First Ill setup the networks. The following script creates two network namesapces. One with an IPv6 veth pair and one with an IPv4 pair.

```
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

$ ip netns ls
ipv6 (id: 1)
ipv4 (id: 0)

```
Ill also start the translation container with the IPv4 net ns.

```
$ sudo ctr run -t --rm --with-ns network:/var/run/netns/ipv4 docker.io/nicolaka/netshoot:latest ipv4container bash
b3k3r-ubuntu-ipv4:~# ip a show
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
    inet6 ::1/128 scope host 
       valid_lft forever preferred_lft forever
15: eth0@if16: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UP group default qlen 1000
    link/ether 1e:b7:ad:2f:15:ef brd ff:ff:ff:ff:ff:ff link-netnsid 0
    inet 192.168.100.2/24 scope global eth0
       valid_lft forever preferred_lft forever
    inet6 fe80::1cb7:adff:fe2f:15ef/64 scope link 
       valid_lft forever preferred_lft forever
b3k3r-ubuntu-ipv4:~# ip route show
default via 192.168.100.1 dev eth0 
192.168.100.0/24 dev eth0 proto kernel scope link src 192.168.100.2
```
I also have an nginx container running on my host so I can test curl 

```
b3k3r-ubuntu-ipv4:~# strace -e trace=socket,connect curl 172.17.0.2
socket(AF_INET, SOCK_STREAM|SOCK_NONBLOCK, IPPROTO_TCP) = 4
connect(4, {sa_family=AF_INET, sin_port=htons(80), sin_addr=inet_addr("172.17.0.2")}, 16) = -1 EINPROGRESS (Operation in progress)
<!DOCTYPE html>
<html>
<head>
<title>Welcome to nginx!</title>
<style>
html { color-scheme: light dark; }
body { width: 35em; margin: 0 auto;
font-family: Tahoma, Verdana, Arial, sans-serif; }
</style>
</head>
<body>
<h1>Welcome to nginx!</h1>
<p>If you see this page, the nginx web server is successfully installed and
working. Further configuration is required.</p>

<p>For online documentation and support please refer to
<a href="http://nginx.org/">nginx.org</a>.<br/>
Commercial support is available at
<a href="http://nginx.com/">nginx.com</a>.</p>

<p><em>Thank you for using nginx.</em></p>
</body>
</html>
+++ exited with 0 +++
```

Now Ill start my IPv6 container. We can view the network and set a baseline.

```
$ sudo ctr run -t --rm --seccomp=true --seccomp-profile ./profiles/notify.json --with-ns network:/var/run/netns/ipv6 docker.io/nicolaka/netshoot:latest ipv6container bash
b3k3r-ubuntu-ipv6:~# ip a show; ip -6 route show
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
    inet6 ::1/128 scope host 
       valid_lft forever preferred_lft forever
17: eth0@if18: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UP group default qlen 1000
    link/ether ae:99:8b:6c:22:39 brd ff:ff:ff:ff:ff:ff link-netnsid 0
    inet6 fd00:dead:beef::2/64 scope global 
       valid_lft forever preferred_lft forever
    inet6 fe80::ac99:8bff:fe6c:2239/64 scope link 
       valid_lft forever preferred_lft forever
fd00:dead:beef::/64 dev eth0 proto kernel metric 256 pref medium
fe80::/64 dev eth0 proto kernel metric 256 pref medium
default via fd00:dead:beef::1 dev eth0 metric 1024 pref medium

# I can ping the gateway (host veth side interface)

b3k3r-ubuntu-ipv6:~# ping -c1 fd00:dead:beef::1
PING fd00:dead:beef::1 (fd00:dead:beef::1) 56 data bytes
64 bytes from fd00:dead:beef::1: icmp_seq=1 ttl=64 time=0.077 ms

--- fd00:dead:beef::1 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 0.077/0.077/0.077/0.000 ms

b3k3r-ubuntu-ipv6:~# strace -e trace=connect,socket curl 172.17.0.2
socket(AF_INET, SOCK_STREAM|SOCK_NONBLOCK, IPPROTO_TCP) = 4
connect(4, {sa_family=AF_INET, sin_port=htons(80), sin_addr=inet_addr("172.17.0.2")}, 16) = -1 ENOSYS (Function not implemented)
curl: (7) Failed to connect to 172.17.0.2 port 80 after 0 ms: Could not connect to server
+++ exited with 7 +++
```
From the above we can see the IPv6 network but I cannot ping the nginx container on my host.

Next Ill build the agent, run it, then watch its systemcall stack (only a few) with strace. FYI, the build uses the custom libseccomp API build from the addFD PR. The translation PID is the IPv4 container we will use to call connect from.

```
$ sudo ctr tasks list
TASK             PID       STATUS    
ipv4container    246136    RUNNING

$ PKG_CONFIG_PATH=~/Development/libseccomp/prefix/lib/pkgconfig go build -o bin/main main.go
$ sudo TRANSLATION_PID=246136 LD_PRELOAD=~/Development/libseccomp/prefix/lib/libseccomp.so ./bin/main 
2025/08/16 19:49:39 Listening on /run/seccomp-agent.socket : new
2025/08/16 19:49:39 Waiting for connection...

$ p=$(ps -ax | grep "0:00 ./bin/main" | awk '{print $1}' | head -n1)
$ sudo strace -p $p -f -e trace=openat,setns,socket,ioctl,connect
strace: Process 245798 attached with 6 threads
```

When I restart my IPv6 container. The seccomp-agent starts polling for notificiations as part of the runc container Init process 

```
$ sudo TRANSLATION_PID=246136 LD_PRELOAD=~/Development/libseccomp/prefix/lib/libseccomp.so ./bin/main 
2025/08/16 20:03:57 Listening on /run/seccomp-agent.socket : new
2025/08/16 20:03:57 Waiting for connection...
2025/08/16 20:05:29 Waiting for connection...
2025/08/16 20:05:29 Accepted connection on FD 4

$ sudo strace -p $p -f -e trace=openat,setns,socket,ioctl,connect
strace: Process 246450 attached with 6 threads
[pid 246450] --- SIGURG {si_signo=SIGURG, si_code=SI_TKILL, si_pid=246450, si_uid=0} ---
[pid 246450] ioctl(6, SECCOMP_IOCTL_NOTIF_RECV,
```

Now the moment of truth. Ill run the same curl command as above from my IPv6 container with the seccomp-agent running 

```
b3k3r-ubuntu-ipv6:~# strace -e trace=connect,socket curl 172.17.0.2
socket(AF_INET, SOCK_STREAM|SOCK_NONBLOCK, IPPROTO_TCP) = 4
connect(4, {sa_family=AF_INET, sin_port=htons(80), sin_addr=inet_addr("172.17.0.2")}, 16) = 0
<!DOCTYPE html>
<html>
<head>
<title>Welcome to nginx!</title>
<style>
html { color-scheme: light dark; }
body { width: 35em; margin: 0 auto;
font-family: Tahoma, Verdana, Arial, sans-serif; }
</style>
</head>
<body>
<h1>Welcome to nginx!</h1>
<p>If you see this page, the nginx web server is successfully installed and
working. Further configuration is required.</p>

<p>For online documentation and support please refer to
<a href="http://nginx.org/">nginx.org</a>.<br/>
Commercial support is available at
<a href="http://nginx.com/">nginx.com</a>.</p>

<p><em>Thank you for using nginx.</em></p>
</body>
</html>
+++ exited with 0 +++

$ sudo TRANSLATION_PID=246136 LD_PRELOAD=~/Development/libseccomp/prefix/lib/libseccomp.so ./bin/main 
2025/08/16 20:21:22 Listening on /run/seccomp-agent.socket : new
2025/08/16 20:21:22 Waiting for connection...
2025/08/16 20:21:33 Waiting for connection...
2025/08/16 20:21:33 Accepted connection on FD 4
2025/08/16 20:32:23 Received syscall request
2025/08/16 20:32:23 Handling connect syscall for PID 248041
2025/08/16 20:32:23 Args:  [4 140637966538968 16 0 0 0]
2025/08/16 20:32:23 seeking to 140637966538968 and reading 16 from /proc/248041/mem
2025/08/16 20:32:23 Socker addr of type: &{2 20480 [172 17 0 2] [0 0 0 0 0 0 0 0]}, IP/Port: 172.17.0.2:80
2025/08/16 20:32:23 Received a valid IPv4 address on an IPv6 network. Attempting ADD_FD from translation net NS
2025/08/16 20:32:23 attempting connect at:  {80 [172 17 0 2] {0 0 [0 0 0 0] [0 0 0 0 0 0 0 0]}}
2025/08/16 20:32:23 Connect translation successful. New FD: 4

$ sudo strace -p $p -f -e trace=openat,setns,socket,ioctl,connect
strace: Process 247639 attached with 6 threads
[pid 247641] ioctl(6, SECCOMP_IOCTL_NOTIF_RECV, {id=0x60bf77f9099c2eb3, pid=248041, flags=0, data={nr=__NR_connect, arch=AUDIT_ARCH_X86_64, instruction_pointer=0x7fe8d4ae64c0, args=[0x4, 0x7fe8d40998d8, 0x10, 0, 0, 0]}}) = 0
[pid 247641] --- SIGURG {si_signo=SIGURG, si_code=SI_TKILL, si_pid=247639, si_uid=0} ---
[pid 247643] openat(AT_FDCWD, "/proc/248041/mem", O_RDONLY|O_CLOEXEC) = 7
[pid 247643] ioctl(6, SECCOMP_IOCTL_NOTIF_ID_VALID, [0x60bf77f9099c2eb3]) = 0
[pid 247643] openat(AT_FDCWD, "/proc/self/ns/net", O_RDONLY|O_CLOEXEC) = 7
[pid 247643] openat(AT_FDCWD, "/proc/246136/ns/net", O_RDONLY|O_CLOEXEC) = 10
[pid 247643] setns(10, CLONE_NEWNET)    = 0
[pid 247643] socket(AF_INET, SOCK_STREAM, IPPROTO_TCP) = 10
[pid 247643] connect(10, {sa_family=AF_INET, sin_port=htons(80), sin_addr=inet_addr("172.17.0.2")}, 16) = 0
[pid 247643] ioctl(6, SECCOMP_IOCTL_NOTIF_ADDFD, {id=0x60bf77f9099c2eb3, flags=SECCOMP_ADDFD_FLAG_SETFD, srcfd=10, newfd=4, newfd_flags=O_CLOEXEC}) = 4
[pid 247643] setns(7, CLONE_NEWNET)     = 0
[pid 247643] ioctl(6, SECCOMP_IOCTL_NOTIF_SEND, {id=0x60bf77f9099c2eb3, val=0, error=0, flags=0}) = 0
[pid 247643] ioctl(6, SECCOMP_IOCTL_NOTIF_RECV,
```

It worked!! (or so I think?)

The above logs/strace ouptut is quite interesting to view in the context of the implementation. 

curl is nice but Im curious about a persistent connection. Im going to try netcat to see how the impl handles that.
```
66de0f747ac1:~# nc -v -l -p 5000
Listening on 0.0.0.0 5000
Connection received on 192.168.100.2 56252
hi
hello

b3k3r-ubuntu-ipv6:~# nc -v 172.17.0.3 5000
Connection to 172.17.0.3 5000 port [tcp/*] succeeded!
hi
hello

2025/08/16 21:08:08 Received syscall request
2025/08/16 21:08:08 Handling connect syscall for PID 249469
2025/08/16 21:08:08 Args:  [3 140197983083216 16 0 0 0]
2025/08/16 21:08:08 seeking to 140197983083216 and reading 16 from /proc/249469/mem
2025/08/16 21:08:08 Socker addr of type: &{2 34835 [172 17 0 3] [0 0 0 0 0 0 0 0]}, IP/Port: 172.17.0.3:5000
2025/08/16 21:08:08 Received a valid IPv4 address on an IPv6 network. Attempting ADD_FD from translation net NS
2025/08/16 21:08:08 attempting connect at:  {5000 [172 17 0 3] {0 0 [0 0 0 0] [0 0 0 0 0 0 0 0]}}
2025/08/16 21:08:08 Connect translation successful. New FD: 3

[pid 247639] ioctl(7, SECCOMP_IOCTL_NOTIF_RECV, {id=0xb85dd5c61b785a32, pid=249469, flags=0, data={nr=__NR_connect, arch=AUDIT_ARCH_X86_64, instruction_pointer=0x7f8262f704c0, args=[0x3, 0x7f8262fadad0, 0x10, 0, 0, 0]}}) = 0
[pid 247639] openat(AT_FDCWD, "/proc/249469/mem", O_RDONLY|O_CLOEXEC) = 11
[pid 247639] ioctl(7, SECCOMP_IOCTL_NOTIF_ID_VALID, [0xb85dd5c61b785a32]) = 0
[pid 247639] --- SIGURG {si_signo=SIGURG, si_code=SI_TKILL, si_pid=247639, si_uid=0} ---
[pid 249463] openat(AT_FDCWD, "/proc/self/ns/net", O_RDONLY|O_CLOEXEC) = 11
[pid 249463] openat(AT_FDCWD, "/proc/246136/ns/net", O_RDONLY|O_CLOEXEC) = 12
[pid 249463] setns(12, CLONE_NEWNET)    = 0
[pid 249463] socket(AF_INET, SOCK_STREAM, IPPROTO_TCP) = 12
[pid 249463] connect(12, {sa_family=AF_INET, sin_port=htons(5000), sin_addr=inet_addr("172.17.0.3")}, 16) = 0
[pid 249463] ioctl(7, SECCOMP_IOCTL_NOTIF_ADDFD, {id=0xb85dd5c61b785a32, flags=SECCOMP_ADDFD_FLAG_SETFD, srcfd=12, newfd=3, newfd_flags=O_CLOEXEC}) = 3
[pid 249463] setns(11, CLONE_NEWNET)    = 0
[pid 249463] ioctl(7, SECCOMP_IOCTL_NOTIF_SEND, id=0xb85dd5c61b785a32, val=0, error=0, flags=0}) = 0
[pid 249463] ioctl(7, SECCOMP_IOCTL_NOTIF_RECV,
```

Looks like the same. And I can send a recieve messages from both sides over the TCP connection. Wow! It feels a bit like magic.

### Summary and Thoughts 

This was fun to dive into. Some points I picked up through this process 

* Handling UDS - This is something I do much less of day-to-day. Things like parsing SCM_RIGHTS are also a big new to me.
* Learning about Seccomp - The capabilities here are much more interesting than I prevously thought. Building an agent that can react and act as an enforcer directly in the syscall path is pretty cool.
* Go/C Bindings - I dont do much of this in my day-to-day either so it was cool to build my own custom libseccomp API .so files and dynamically link them in.
* Sockets, file descriptors, syscalls - I do from time to time do syscall analysis in my day job, so this I was used to. But I dont get to experiment with these fundamental unix/linux concepts directly. So much has been abstracted away these days, its nice to move down the stack.
* runc code inspection - Looking at the seccomp profile implementation gave me a better idea of how runc works under the covers. How containerd handles creating containers. I use k8s in my day job so I know a bunch about these concpets but not at such an intimate level. Again, abstraction....

Overall I think implementing this as a weekend project was well worth the experience. And I look forward to future thinks like this. May they be a fruitful and successful (as they not always are!).

### Extra 

#### eBPF

TODO

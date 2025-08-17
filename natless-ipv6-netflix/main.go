package main

import (
	"encoding/json"
	"fmt"
	"log"
	"math"
	"net"
	"os"
	"runtime"
	"strconv"
	"syscall"
	"unsafe"

	libseccomp "github.com/seccomp/libseccomp-golang"
	"golang.org/x/sys/unix"

	specs "github.com/opencontainers/runtime-spec/specs-go"
)

const socketPath = "/run/seccomp-agent.socket"

func main() {
	if err := os.RemoveAll(socketPath); err != nil {
		log.Printf("Warning: Socket removal failed: %v", err)
	}
	listener, err := unix.Socket(unix.AF_UNIX, unix.SOCK_STREAM, 0)
	if err != nil {
		log.Fatalf("Socket creation error: %v", err)
	}
	addr := &unix.SockaddrUnix{Name: socketPath}
	if err := unix.Bind(listener, addr); err != nil {
		log.Fatalf("Socket bind error: %v", err)
	}
	if err := os.Chmod(socketPath, 0666); err != nil {
		log.Fatalf("Socket permission error: %v", err)
	}
	BACKLOG := 100
	if err := unix.Listen(listener, BACKLOG); err != nil {
		log.Fatalf("Socket listen error: %v", err)
	}
	defer unix.Close(listener)

	log.Printf("Listening on %s : new", socketPath)

	for {
		log.Printf("Waiting for connection...")
		fd, _, err := unix.Accept(listener)
		if err != nil {
			log.Printf("accept error on UDS listener for path %v: %v", socketPath, err)
			continue
		}
		go streamFDHandler(fd)
	}
}

// streamFDHandler handles the accepted socket file descriptor data stream. We expect
// to read SCM_RIGHTS from the FD, which should container the seccomp notify FD and OCI state.
func streamFDHandler(fd int) {
	log.Printf("Accepted connection on FD %d", fd)
	defer unix.Close(fd)

	handler, err := newScmpHandler(fd)
	if err != nil {
		log.Printf("Error creating scmpHandler: %v", err)
		return
	}
	defer handler.Close()

	// TODO: Is there any error we would want to return on?
	// Once we return, would we ever enter back for a given container until it restarts?
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
}

// scmpHandler handles userpsace seccomp notify requests.
// Every container would get its own handler as it starts up.
type scmpHandler struct {
	ociState specs.ContainerProcessState
	notifyFd libseccomp.ScmpFd
}

func newScmpHandler(fd int) (*scmpHandler, error) {
	notifyFd, stateData, err := recvSCMRightsToScmpFD(fd)
	if err != nil {
		return nil, fmt.Errorf("error receiving SCM_RIGHTS on fd: %v", err)
	}
	// We know runc provides the OCI state data as non-control message data.
	// We will unmarshal this so we can use it later.
	ociState := specs.ContainerProcessState{}
	if err := json.Unmarshal(stateData, &ociState); err != nil {
		syscall.Close(int(notifyFd)) // Close notifyFd
		return nil, fmt.Errorf("error unmarshling oci state data: %v", err)
	}

	return &scmpHandler{
		ociState: ociState,
		notifyFd: notifyFd,
	}, nil
}

func (h *scmpHandler) Close() {
	unix.Close(int(h.notifyFd))
}

func (h *scmpHandler) RecieveAndHandle() (libseccomp.ScmpNotifResp, error) {
	req, err := libseccomp.NotifReceive(h.notifyFd)
	if err != nil {
		return libseccomp.ScmpNotifResp{}, fmt.Errorf("notif recieve error: %v", err)
	}
	log.Printf("Received syscall request")
	return h.handleSyscall(req), nil
}

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

func (h *scmpHandler) handleConnect(
	req *libseccomp.ScmpNotifReq,
	resp libseccomp.ScmpNotifResp,
) libseccomp.ScmpNotifResp {
	buf, err := readConnectRemoteMemory(req, h.notifyFd)
	if err != nil {
		log.Printf("error reading remote memory: %v", err)
		return resp
	}
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
	case unix.AF_INET6:
		sa := (*unix.RawSockaddrInet6)(unsafe.Pointer(rsa))
		log.Printf("Socker addr of type: %v, IP/Port: %v:%v\n", sa, net.IP(sa.Addr[:]), int(sa.Port>>8|sa.Port<<8))
	}
	resp.Error = 0
	resp.Val = 0
	resp.Flags = 0
	return resp
}

// containerNetworkMatchesSocketType
func containerNetworkMatchesSocketType() bool {
	return false
}

// hostHasIPv4Route will ensure the host has a route that can handle the requested
// destination IPv4 address. Otherwise it would be pointless for us to try to
// connect to it via some IPv4 FD as the connect call would return the same error.
// This would be the case if the VM had an IPv6 stack and no IPv4 interface/routing was added.
// NOTE: For now we will assume a route is always there.
func hostHasIPv4Route() bool {
	return true
}

// This is the PID of the container we want to create a connect call against. It would have
// an IPv4 network stack and should be able to serve the IPv4 request.
var translationPID int

func (h *scmpHandler) addFD(req *libseccomp.ScmpNotifReq, sa *unix.RawSockaddrInet4) (int, error) {
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

	// Now we are in the translation netns. We can create an IPv4 socket to obtain its FD.
	// NOTE: not sure who will close this FD. Need to accout for this.
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

func enterNetNS(targetPID int) error {
	// Lock to the current OS thread so the namespace change only affects this thread
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	targetPath := fmt.Sprintf("/proc/%d/ns/net", targetPID)
	target, err := os.Open(targetPath)
	if err != nil {
		return fmt.Errorf("error opening target PID ns: %w", err)
	}
	defer target.Close()

	if err := unix.Setns(int(target.Fd()), unix.CLONE_NEWNET); err != nil {
		return fmt.Errorf("error running setns on target: %w", err)
	}
	return nil
}

// Example parse for sockaddr_in (16 bytes)
func parseSockaddr(data []byte) *unix.RawSockaddrAny {
	buf := make([]byte, unix.SizeofSockaddrAny)
	copy(buf, data)
	rawSockaddr := (*unix.RawSockaddrAny)(unsafe.Pointer(&buf[0]))
	return rawSockaddr
}

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

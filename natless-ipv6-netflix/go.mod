module natless-ipv6

go 1.24.3

require (
	github.com/opencontainers/runtime-spec v1.2.1
	github.com/seccomp/libseccomp-golang v0.11.1
	golang.org/x/sys v0.34.0
)

replace github.com/seccomp/libseccomp-golang v0.11.1 => /home/brendan/Development/libseccomp-golang

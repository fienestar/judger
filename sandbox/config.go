package sandbox

import "github.com/elastic/go-seccomp-bpf"

type SandboxConfig struct {
	Target    SandboxTarget
	MemLimit  int64 // bytes
	TimeLimit int64 // ms
	MaxOutput int64
	Policy    *seccomp.Policy
	ErrorPath string
}

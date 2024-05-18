package sandbox

type SandboxStatusCode int64

const (
	Success SandboxStatusCode = iota
	TimeLimitExceeded
	MemoryLimitExceeded
	DupError
	OpenError
	RuntimeError
	ForkError
	SeccompError
	ExecveError
)

type SandboxStatus struct {
	Code      SandboxStatusCode
	MemUsed   int64
	TimeSpent int64
	Msg       string
}

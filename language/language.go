package language

import (
	"judger/sandbox"

	"github.com/elastic/go-seccomp-bpf"
)

type LimitConversion struct {
	Coef  float64 `yaml:"coef"`
	Extra float64 `yaml:"extra"`
}

type CompileLimit struct {
	Time   int64 `yaml:"time"`
	Memory int64 `yaml:"memory"`
}

type Language struct {
	Name         string                `yaml:"name"`
	Compile      sandbox.SandboxTarget `yaml:"compile"`
	CompileLimit CompileLimit          `yaml:"compile_limit"`
	Execute      sandbox.SandboxTarget `yaml:"execute"`
	Time         LimitConversion       `yaml:"time"`
	Memory       LimitConversion       `yaml:"memory"`
	Policy       seccomp.Policy        `yaml:"policy"`
}

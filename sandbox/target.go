package sandbox

type SandboxTarget struct {
	Pathname   string
	Argv       []string
	Envp       []string
	InputPath  string `yaml:"input_path"`
	OutputPath string `yaml:"output_path"`
	ErrorPath  string `yaml:"error_path"`
}

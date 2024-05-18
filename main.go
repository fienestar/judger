package main

import (
	"fmt"
	"judger/language"
	"judger/sandbox"
	"os"

	"gopkg.in/yaml.v3"
)

func main() {
	if language, err := readLanguageFile("./languages/sample.yaml"); err != nil {
		fmt.Println(err)
	} else {
		fmt.Println("language", *language)

		res := sandbox.RunSandbox(sandbox.SandboxConfig{
			Target:    language.Compile,
			MemLimit:  language.CompileLimit.Memory,
			TimeLimit: language.CompileLimit.Time,
			MaxOutput: -1,
			ErrorPath: "./test/error.txt",
		})

		fmt.Println("compile:", res)

		fmt.Println("language", *language)

		res = sandbox.RunSandbox(sandbox.SandboxConfig{
			Target:    language.Execute,
			MemLimit:  268435456,
			TimeLimit: 1000,
			MaxOutput: 1024 * 1024,
			ErrorPath: "./test/error.txt",
			Policy:    &language.Policy,
		})

		fmt.Println("execute:", res)
	}
}

func readLanguageFile(path string) (*language.Language, error) {
	type Config struct {
		Version  string
		Language language.Language
	}

	yamlFile, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var config Config
	if err := yaml.Unmarshal(yamlFile, &config); err != nil {
		return nil, err
	}

	return &config.Language, nil
}

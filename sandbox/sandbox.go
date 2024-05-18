package sandbox

/*
#include <stdlib.h>
*/
import "C"

import (
	"fmt"
	"os"
	"strings"
	"syscall"
	"unsafe"

	"github.com/elastic/go-seccomp-bpf"
)

func RunSandbox(config SandboxConfig) SandboxStatus {
	error_file, err := os.OpenFile(config.ErrorPath, os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return SandboxStatus{
			Code:      OpenError,
			MemUsed:   -1,
			TimeSpent: -1,
			Msg:       "failed to open error file for sandbox",
		}
	}

	denyDetours(config)
	defer allowExecveForTarget(config)()

	//TODO: fork() may be unsafe in go. need to create new process.
	pid := func() int {
		pid, _, _ := syscall.Syscall(syscall.SYS_FORK, 0, 0, 0)
		return int(pid)
	}()

	if pid < 0 {
		return SandboxStatus{
			Code:      ForkError,
			MemUsed:   -1,
			TimeSpent: -1,
			Msg:       "failed to fork",
		}
	}

	var time_begin, time_end syscall.Timeval
	syscall.Gettimeofday(&time_begin)

	if pid == 0 { // child
		status := runSandboxChild(config) // will never return if successful
		writeError(error_file, status)
		os.Exit(-1)
	}

	error_file.Close()

	var rusage syscall.Rusage
	var status syscall.WaitStatus
	_, err = syscall.Wait4(int(pid), &status, 0, &rusage)
	if err != nil {
		return SandboxStatus{
			Code:      RuntimeError,
			MemUsed:   -1,
			TimeSpent: -1,
			Msg:       fmt.Sprintf("failed to wait4: %v", err),
		}
	}
	syscall.Gettimeofday(&time_end)
	time_spent := (time_end.Sec*1000 + time_end.Usec/1000) - (time_begin.Sec*1000 + time_begin.Usec/1000)
	memory_used := rusage.Maxrss * 1024

	cpu_time := rusage.Stime.Sec*1000 + rusage.Stime.Usec/1000
	if config.TimeLimit > 0 && cpu_time > config.TimeLimit/1000 && time_spent > config.TimeLimit {
		return SandboxStatus{
			Code:      TimeLimitExceeded,
			MemUsed:   memory_used,
			TimeSpent: time_spent,
			Msg:       "time limit exceeded",
		}
	}

	if config.MemLimit > 0 && memory_used > config.MemLimit {
		return SandboxStatus{
			Code:      MemoryLimitExceeded,
			MemUsed:   memory_used,
			TimeSpent: time_spent,
			Msg:       "memory limit exceeded",
		}
	}

	exit_code := status.ExitStatus()
	signal := syscall.Signal(0)
	if status.Signaled() {
		signal = status.Signal()
	}

	if exit_code != 0 || signal != syscall.Signal(0) {
		return SandboxStatus{
			Code:      RuntimeError,
			MemUsed:   memory_used,
			TimeSpent: time_spent,
			Msg:       fmt.Sprintf("exit code: %d, signal: %d", exit_code, signal),
		}
	}

	return SandboxStatus{
		Code:      Success,
		MemUsed:   memory_used,
		TimeSpent: time_spent,
		Msg:       "success",
	}
}

func runSandboxChild(config SandboxConfig) SandboxStatus {
	if err_status := setStdStreams(config); err_status != nil {
		return *err_status
	}
	setrlimits(config)

	if config.Policy != nil {
		if err := seccomp.LoadFilter(seccomp.Filter{
			NoNewPrivs: true,
			Flag:       seccomp.FilterFlagTSync,
			Policy:     *config.Policy,
		}); err != nil {
			return SandboxStatus{
				Code:      SeccompError,
				MemUsed:   -1,
				TimeSpent: -1,
				Msg:       fmt.Sprintf("failed to load seccomp filter: %v", err),
			}
		}
	}

	target := config.Target
	argv := append([]string{target.Pathname}, target.Argv...)
	envp := append([]string{
		"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
	}, target.Envp...)

	for i := range argv {
		argv[i] = strings.TrimSpace(argv[i])
	}

	for i := range envp {
		envp[i] = strings.TrimSpace(envp[i])
	}

	syscall.Exec(target.Pathname, argv, envp)
	return SandboxStatus{
		Code:      ExecveError,
		MemUsed:   -1,
		TimeSpent: -1,
		Msg:       "failed to execve", //TODO: errno
	}
}

func setStdStreams(config SandboxConfig) *SandboxStatus {
	open_paths := []string{config.Target.InputPath, config.Target.OutputPath, config.Target.ErrorPath}
	open_flags := []int{os.O_RDONLY, os.O_WRONLY | os.O_CREATE, os.O_WRONLY | os.O_CREATE}

	for i, path := range open_paths {
		if path == "" {
			continue
		}
		file, err := os.OpenFile(path, open_flags[i], 0644)
		if err != nil {
			return &SandboxStatus{
				Code:      OpenError,
				MemUsed:   -1,
				TimeSpent: -1,
				Msg:       fmt.Sprintf("failed to open %s: %v", path, err),
			}
		}
		err = syscall.Dup2(int(file.Fd()), i)
		if err != nil {
			return &SandboxStatus{
				Code:      DupError,
				MemUsed:   -1,
				TimeSpent: -1,
				Msg:       fmt.Sprintf("failed to dup2: %v", err),
			}
		}
	}

	return nil
}

func allowExecveForTarget(config SandboxConfig) func() {
	if config.Policy == nil {
		return func() {}
	}

	cpath := unsafe.Pointer(C.CString(config.Target.Pathname))
	config.Policy.Syscalls = append(config.Policy.Syscalls, seccomp.SyscallGroup{
		Action: seccomp.ActionAllow,
		NamesWithCondtions: []seccomp.NameWithConditions{
			{
				Name: "execve",
				Conditions: []seccomp.Condition{
					{
						Argument:  0,
						Operation: seccomp.Equal,
						Value:     uint64(uintptr(cpath)),
					},
				},
			},
		},
	})
	return func() { C.free(cpath) }
}

func ActionErrno(x uint32) seccomp.Action {
	return seccomp.Action(uint32(seccomp.ActionErrno) | (x & 0xffff))
}

const EACCES = 13

func denyDetours(config SandboxConfig) {
	if config.Policy == nil {
		return
	}

	if config.Policy.DefaultAction == seccomp.ActionAllow {
		config.Policy.Syscalls = append(config.Policy.Syscalls, seccomp.SyscallGroup{
			Action: seccomp.ActionKillThread,
			Names:  []string{"fork", "vfork", "clone", "execve", "execveat", "kill", "setrlimit"},
		})

		flags := []int{os.O_WRONLY, os.O_RDWR, os.O_CREATE}
		for _, flag := range flags {
			config.Policy.Syscalls = append(config.Policy.Syscalls, seccomp.SyscallGroup{
				Action: seccomp.ActionKillThread,
				Names:  []string{},
				NamesWithCondtions: []seccomp.NameWithConditions{
					{
						Name: "open",
						Conditions: []seccomp.Condition{
							{
								Argument:  1,
								Operation: seccomp.BitsSet,
								Value:     uint64(flag),
							},
						},
					}, {
						Name: "openat",
						Conditions: []seccomp.Condition{
							{
								Argument:  2,
								Operation: seccomp.BitsSet,
								Value:     uint64(flag),
							},
						},
					},
				},
			})
		}
	} else {
		config.Policy.Syscalls = append(config.Policy.Syscalls, seccomp.SyscallGroup{
			Action: seccomp.ActionAllow,
			NamesWithCondtions: []seccomp.NameWithConditions{
				{
					Name: "open",
					Conditions: []seccomp.Condition{
						{
							Argument:  1,
							Operation: seccomp.BitsNotSet,
							Value:     uint64(os.O_WRONLY | os.O_RDWR | os.O_CREATE),
						},
					},
				},
				{
					Name: "openat",
					Conditions: []seccomp.Condition{
						{
							Argument:  2,
							Operation: seccomp.BitsNotSet,
							Value:     uint64(os.O_WRONLY | os.O_RDWR | os.O_CREATE),
						},
					},
				},
			},
		})
	}

	config.Policy.Syscalls = append(config.Policy.Syscalls, seccomp.SyscallGroup{
		Action: ActionErrno(EACCES),
		Names:  []string{"socket"},
	})
}

func setrlimits(config SandboxConfig) {
	if config.TimeLimit > 0 {
		syscall.Setrlimit(syscall.RLIMIT_CPU, &syscall.Rlimit{
			Cur: uint64(config.TimeLimit/1000 + 2),
			Max: uint64(config.TimeLimit/1000 + 2),
		})
	}
	if config.MemLimit > 0 {
		syscall.Setrlimit(syscall.RLIMIT_AS, &syscall.Rlimit{
			Cur: uint64(config.MemLimit + config.MemLimit/5),
			Max: uint64(config.MemLimit + config.MemLimit/5),
		})
	}
	if config.MaxOutput > 0 {
		syscall.Setrlimit(syscall.RLIMIT_FSIZE, &syscall.Rlimit{
			Cur: uint64(config.MaxOutput + 1000),
			Max: uint64(config.MaxOutput + 1000),
		})
	}
}

func writeError(error_file *os.File, status SandboxStatus) {
	error_file.WriteString(fmt.Sprintf("%d\n", status.Code))
	error_file.WriteString(fmt.Sprintf("%s\n", status.Msg))
}

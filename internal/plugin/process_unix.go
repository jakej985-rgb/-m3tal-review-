//go:build !windows

package plugin

import (
	"os/exec"
	"syscall"
)

// preparePluginCmd configures OS process group isolation and cancellation behavior
// so that context cancellation terminates the entire process tree rather than leaving
// orphan child processes running.
func preparePluginCmd(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Setpgid: true,
	}
	cmd.Cancel = func() error {
		if cmd.Process != nil && cmd.Process.Pid > 0 {
			if err := syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL); err != nil && err != syscall.ESRCH {
				// Process group may have already terminated
			}
		}
		return killProcess(cmd)
	}
}

//go:build windows

package plugin

import (
	"os/exec"
)

// preparePluginCmd configures cancellation behavior for Windows plugin processes.
func preparePluginCmd(cmd *exec.Cmd) {
	cmd.Cancel = func() error {
		return killProcess(cmd)
	}
}

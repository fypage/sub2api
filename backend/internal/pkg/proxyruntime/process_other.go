//go:build !(aix || android || darwin || dragonfly || freebsd || illumos || ios || linux || netbsd || openbsd || solaris)

package proxyruntime

import (
	"errors"
	"os"
	"os/exec"
)

func configureProcessGroup(_ *exec.Cmd) {}

func signalProcessGroup(command *exec.Cmd, force bool) error {
	if command == nil || command.Process == nil {
		return os.ErrProcessDone
	}
	if force {
		return command.Process.Kill()
	}
	return command.Process.Signal(os.Interrupt)
}

func isProcessDone(err error) bool {
	return errors.Is(err, os.ErrProcessDone)
}

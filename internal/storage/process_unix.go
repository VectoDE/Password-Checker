//go:build !windows

package storage

import "syscall"

func isProcessRunning(pid int) bool {
	if pid <= 0 {
		return false
	}

	err := syscall.Kill(pid, 0)
	if err == nil {
		return true
	}
	if err == syscall.ESRCH {
		return false
	}

	// For errors like EPERM we conservatively assume the process still exists.
	return true
}

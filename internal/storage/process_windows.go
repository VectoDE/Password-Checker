//go:build windows

package storage

import (
	"errors"
	"syscall"
)

const (
	processQueryLimitedInformation = 0x1000
	stillActive                    = 259
)

var errInvalidParameter = syscall.Errno(87)

func isProcessRunning(pid int) bool {
	if pid <= 0 {
		return false
	}

	handle, err := syscall.OpenProcess(processQueryLimitedInformation, false, uint32(pid))
	if err != nil {
		if errors.Is(err, errInvalidParameter) {
			return false
		}
		// If access is denied or another error occurs, assume the process may still exist.
		return true
	}
	defer syscall.CloseHandle(handle)

	var exitCode uint32
	if err := syscall.GetExitCodeProcess(handle, &exitCode); err != nil {
		return true
	}

	return exitCode == stillActive
}

//go:build windows

package storage

import (
	"errors"
	"syscall"
)

func isProcessRunning(pid int) bool {
	if pid <= 0 {
		return false
	}

	handle, err := syscall.OpenProcess(syscall.PROCESS_QUERY_LIMITED_INFORMATION, false, uint32(pid))
	if err != nil {
		if errors.Is(err, syscall.ERROR_INVALID_PARAMETER) {
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

	return exitCode == syscall.STILL_ACTIVE
}

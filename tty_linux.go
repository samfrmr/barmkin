//go:build linux

package main

import (
	"os"
	"syscall"
	"unsafe"
)

// isTerminal reports whether f is a terminal.
func isTerminal(f *os.File) bool {
	var t syscall.Termios
	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, f.Fd(), syscall.TCGETS, uintptr(unsafe.Pointer(&t)))
	return errno == 0
}

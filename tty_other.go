//go:build !linux

package main

import "os"

// isTerminal reports no terminal outside Linux, so monitor-admin clear
// refuses rather than guess.
func isTerminal(*os.File) bool { return false }

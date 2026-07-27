//go:build !linux

package main

// hardenMemory is a no-op off Linux; custosd only runs in production on Linux.
func hardenMemory() {}

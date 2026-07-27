package main

import (
	"log"

	"golang.org/x/sys/unix"
)

// hardenMemory keeps opened secrets off swap and out of core dumps. Best-effort:
// a failure (e.g. a low RLIMIT_MEMLOCK) is logged, not fatal.
func hardenMemory() {
	if err := unix.Mlockall(unix.MCL_CURRENT | unix.MCL_FUTURE); err != nil {
		log.Printf("harden: mlockall failed (%v); secrets may reach swap", err)
	}
	if err := unix.Prctl(unix.PR_SET_DUMPABLE, 0, 0, 0, 0); err != nil {
		log.Printf("harden: PR_SET_DUMPABLE failed: %v", err)
	}
	if err := unix.Setrlimit(unix.RLIMIT_CORE, &unix.Rlimit{Cur: 0, Max: 0}); err != nil {
		log.Printf("harden: disabling core dumps failed: %v", err)
	}
}

//go:build linux

// openvpnmultu_cpu.go — pin each OpenVPN worker process to a dedicated CPU core.
package platform

import (
	"fmt"
	"runtime"

	"golang.org/x/sys/unix"
)

// openvpnMultuWorkerCPU maps worker index → CPU core (round-robin when workers > cores).
func OpenvpnMultuWorkerCPU(index int) int {
	n := runtime.NumCPU()
	if n <= 0 {
		return 0
	}
	return index % n
}

func PinOpenVPNWorkerCPU(pid, cpu int) error {
	if pid <= 0 {
		return fmt.Errorf("invalid pid %d", pid)
	}
	var set unix.CPUSet
	set.Zero()
	set.Set(cpu)
	return unix.SchedSetaffinity(pid, &set)
}

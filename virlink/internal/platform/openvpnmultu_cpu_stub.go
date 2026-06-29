//go:build !linux

package platform

import "fmt"

func openvpnMultuWorkerCPU(index int) int { return index }

func pinOpenVPNWorkerCPU(pid, cpu int) error {
	return fmt.Errorf("CPU pinning requires linux")
}

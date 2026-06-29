//go:build !linux

package virlink

func tunPending(fd int) int { return 1 }

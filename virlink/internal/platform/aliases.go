// aliases.go — lowercase wrappers for same-package brevity.
package platform

import (
	"fmt"
	"net"

	"github.com/vishvananda/netlink"

	"virlink/internal/config"
)

func header(title string)  { Header(title) }
func step(msg string)       { Step(msg) }
func logOK(msg string)      { LogOK(msg) }
func logWarn(msg string)    { LogWarn(msg) }
func logInfo(msg string)    { LogInfo(msg) }
func logError(msg string)   { LogError(msg) }
func logDebug(msg string)   { LogDebug(msg) }
func warn(msg string)       { LogWarn(msg) }
func done(iface, overlay, peer string, extras ...string) {
	Done(iface, overlay, peer, extras...)
}
func try(name string, args ...string)                    { Try(name, args...) }
func run(name string, args ...string) error              { return Run(name, args...) }
func runOut(name string, args ...string) (string, error) { return RunOut(name, args...) }
func iptablesEnsure(rule []string)                       { IptablesEnsure(rule) }
func tuneUDPConn(conn *net.UDPConn)                      { TuneUDPConn(conn) }
func getBuf() []byte                                     { return GetBuf() }
func putBuf(b []byte)                                    { PutBuf(b) }
func tuneRawSock(fd int)                                 { TuneRawSock(fd) }
func hashIPPacket(p []byte) uint32                       { return HashIPPacket(p) }
func loadModules(modules ...string)                      { LoadModules(modules...) }
func openTunMulti(name string, n int) (*TunDev, error) { return OpenTunMulti(name, n) }
func applyPerfFromConfig(c *config.Config)               { ApplyPerfFromConfig(c) }
func parseIcmpWirePacket(pkt []byte, wireOn bool) ([]byte, bool) {
	return ParseIcmpWirePacket(pkt, wireOn)
}

func perfSockBuf() int    { return PerfSockBuf() }
func perfTunQueues() int  { return PerfTunQueues() }
func perfBatchSize() int  { return PerfBatchSize() }
func perfPollMs() int     { return PerfPollMs() }
func perfTcpStreams() int { return PerfTcpStreams() }

func nlRouteDelAll(dst string)                         { NlRouteDelAll(dst) }
func nlRouteDel(dst string)                            { NlRouteDel(dst) }
func nlRouteAdd(dst, dev string) error                 { return NlRouteAdd(dst, dev) }
func nlRouteECMP(dst string, devs ...string) error     { return NlRouteECMP(dst, devs...) }
func nlRouteECMPWithSrc(dst, src string, devs ...string) (int, error) {
	return NlRouteECMPWithSrc(dst, src, devs...)
}
func nlCreate(link netlink.Link, cidr string) error { return NlCreate(link, cidr) }
func nlUp(name string) error                        { return NlUp(name) }
func nlDown(names ...string)                         { NlDown(names...) }
func nlSetMaster(slave, master string) error         { return NlSetMaster(slave, master) }
func nlSysctl(key, val string) error                 { return NlSysctl(key, val) }
func mustIP4(s string) net.IP                        { return MustIP4(s) }

const tunnelEncapFOU = TunnelEncapFOU

func fmtBytes(b uint64) string {
	switch {
	case b < 1024:
		return fmt.Sprintf("%dB", b)
	case b < 1024*1024:
		return fmt.Sprintf("%.1fKB", float64(b)/1024)
	case b < 1024*1024*1024:
		return fmt.Sprintf("%.2fMB", float64(b)/1024/1024)
	default:
		return fmt.Sprintf("%.2fGB", float64(b)/1024/1024/1024)
	}
}

func fmtNum(n uint64) string {
	if n < 1000 {
		return fmt.Sprintf("%d", n)
	} else if n < 1_000_000 {
		return fmt.Sprintf("%.1fK", float64(n)/1000)
	}
	return fmt.Sprintf("%.1fM", float64(n)/1_000_000)
}

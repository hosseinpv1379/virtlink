//go:build linux

package platform

import (
	"os"

	"golang.org/x/sys/unix"
)

const (
	StatICMPTxPoll       = statICMPTxPoll
	StatICMPTxRead       = statICMPTxRead
	StatICMPTxSend       = statICMPTxSend
	StatICMPTxDedup      = statICMPTxDedup
	StatICMPTxNoDst      = statICMPTxNoDst
	StatICMPRxPoll       = statICMPRxPoll
	StatICMPRxRecv       = statICMPRxRecv
	StatICMPRxDropPeer   = statICMPRxDropPeer
	StatICMPRxDropProto  = statICMPRxDropProto
	StatICMPRxDropSeq    = statICMPRxDropSeq
	StatICMPRxWrite      = statICMPRxWrite
	StatICMPRxDropWrite  = statICMPRxDropWrite
	StatBIPTxPoll        = statBIPTxPoll
	StatBIPTxRead        = statBIPTxRead
	StatBIPTxSend        = statBIPTxSend
	StatBIPTxNoDst       = statBIPTxNoDst
	StatBIPRxPoll        = statBIPRxPoll
	StatBIPRxRecv        = statBIPRxRecv
	StatBIPRxDrop        = statBIPRxDrop
	StatBIPRxWrite       = statBIPRxWrite
	StatBIPRxDropWrite   = statBIPRxDropWrite
	StatUDPTxPoll        = statUDPTxPoll
	StatUDPTxRead        = statUDPTxRead
	StatUDPTxSend        = statUDPTxSend
	StatUDPTxNoDst       = statUDPTxNoDst
	StatUDPRxRecv        = statUDPRxRecv
	StatUDPRxDrop        = statUDPRxDrop
	StatUDPRxWrite       = statUDPRxWrite
	StatUDPRxDropWrite   = statUDPRxDropWrite
	StatTCPTxRead        = statTCPTxRead
	StatTCPTxSend        = statTCPTxSend
	StatTCPTxNoConn      = statTCPTxNoConn
	StatTCPRxFrame       = statTCPRxFrame
	StatTCPRxWrite       = statTCPRxWrite
	MaxPktBuf            = maxPktBuf
	TcpRxBufSize         = tcpRxBufSize
)

type IcmpTxBatch = icmpTxBatch
type TunRxBatch = tunRxBatch

func NewTunRxBatch(cap int) tunRxBatch                { return newTunRxBatch(cap) }
func PollFD(fd int, events int16, timeoutMs int) error { return pollFD(fd, events, timeoutMs) }
func IdleBackoff(idleMs, pollMs int) int               { return idleBackoff(idleMs, pollMs) }
func TunWrite(fd *os.File, pkt []byte) error           { return tunWrite(fd, pkt) }
func InstallICMPFilter(fd int) error                   { return installICMPFilter(fd) }
func IcmpSendBatch(rawFd int, b *IcmpTxBatch) int      { return icmpSendBatch(rawFd, b) }
func MmsgSendBatch(rawFd int, b *IcmpTxBatch) int      { return mmsgSendBatch(rawFd, b) }
func NewIcmpTxBatch() *IcmpTxBatch                     { return &IcmpTxBatch{} }
func Contains(s, sub string) bool                      { return contains(s, sub) }
func TcpTxChanCap() int                                { return 256 }

func (b *RxMmsgBatch) Init(n int)                      { b.init(n) }
func (b *RxMmsgBatch) Release()                        { b.release() }
func (b *RxMmsgBatch) Recv(fd int) (int, error)        { return b.recv(fd) }
func (b *RxMmsgBatch) Data(i int) []byte               { return b.data(i) }
func (b *RxMmsgBatch) From4(i int) *unix.SockaddrInet4 { return b.from4(i) }

func (b *TunRxBatch) Add(payload []byte)                { b.add(payload) }
func (b *TunRxBatch) AddOwned(frame []byte, n int)      { b.addOwned(frame, n) }
func (b *TunRxBatch) Len() int                          { return b.len() }
func (b *TunRxBatch) Flush(tun *os.File) (int, error)   { return b.flush(tun) }

func TrimIPv4Packet(pkt []byte) []byte { return trimIPv4Packet(pkt) }

func (b *IcmpTxBatch) N() int { return b.n }
func (b *IcmpTxBatch) Add(frame []byte, pktLen int, dst [4]byte, port uint16) {
	b.add(frame, pktLen, dst, port)
}

func (b *IcmpTxBatch) SetFrame(i int, frame []byte) { b.frames[i] = frame }
func (b *IcmpTxBatch) Frame(i int) []byte { return b.frames[i] }

func (b *IcmpTxBatch) Reset() { b.reset() }
func ReadSysctl(key string) (string, error) { return readSysctl(key) }
func IcmpWireCarrierType(pkt []byte, wireOn bool) byte { return icmpWireCarrierType(pkt, wireOn) }

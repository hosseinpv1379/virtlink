#!/usr/bin/env python3
"""Apply cross-package fixes after package rename."""
import os
import re

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

PKG_MAP = {
    "internal/platform": "platform",
    "internal/wire": "wire",
    "internal/config": "config",
    "internal/app": "app",
    "internal/protocol/tcp": "tcp",
    "internal/protocol/tcpmux": "tcpmux",
    "internal/protocol/udp": "udp",
    "internal/protocol/icmp": "icmp",
    "internal/protocol/bip": "bip",
    "internal/protocol/udpobfs": "udpobfs",
    "internal/protocol/kernel": "kernel",
    "internal/protocol/openvpn": "openvpn",
    "internal/protocol/openvpnmultu": "openvpnmultu",
    "internal/protocol/hysteria2": "hysteria2",
    "internal/protocol/wireguard": "wireguard",
    "internal/protocol/amneziawg": "amneziawg",
}

PROTO_IMPORT = '''import (
\t"virlink/internal/config"
\t"virlink/internal/core"
\t"virlink/internal/platform"
\t"virlink/internal/wire"
'''

PROTO_REPL = [
    (r"\*Config\b", "*config.Config"),
    (r"\bConfig\b", "config.Config"),
    (r"\btunnelDevName\b", "platform.TunnelDevName"),
    (r"\btunnelDevNameWithSuffix\b", "platform.TunnelDevNameWithSuffix"),
    (r"\bopenvpnMultuWorkerDev\b", "platform.OpenvpnMultuWorkerDev"),
    (r"\boverlayAddr\b", "core.OverlayAddr"),
    (r"\bpeerAddr\b", "core.PeerAddr"),
    (r"\bplainIP\b", "core.PlainIP"),
    (r"\bTunDev\b", "platform.TunDev"),
    (r"\bstoppedFlag\b", "platform.StoppedFlag"),
    (r"\batomicSeqDedup\b", "platform.AtomicSeqDedup"),
    (r"\bipPktDedup\b", "platform.IpPktDedup"),
    (r"\bmaxPerfQueues\b", "platform.MaxPerfQueues"),
    (r"\bmaxPerfBatch\b", "platform.MaxPerfBatch"),
    (r"\bhashIPPacket\b", "platform.HashIPPacket"),
    (r"\bipTo4\b", "platform.IpTo4"),
    (r"\bacquireTunnelLock\b", "platform.AcquireTunnelLock"),
    (r"\breleaseTunnelLock\b", "platform.ReleaseTunnelLock"),
    (r"\bopenTunMulti\b", "platform.OpenTunMulti"),
    (r"\bopenTunDev\b", "platform.OpenTunDev"),
    (r"\bheader\b", "platform.Header"),
    (r"\bstep\b", "platform.Step"),
    (r"\blogOK\b", "platform.LogOK"),
    (r"\blogWarn\b", "platform.LogWarn"),
    (r"\blogInfo\b", "platform.LogInfo"),
    (r"\blogError\b", "platform.LogError"),
    (r"\blogDebug\b", "platform.LogDebug"),
    (r"\bdone\b", "platform.Done"),
    (r"\bapplyPerfFromConfig\b", "platform.ApplyPerfFromConfig"),
    (r"\bperfSummary\b", "platform.PerfSummary"),
    (r"\bperfTunQueues\b", "platform.PerfTunQueues"),
    (r"\bperfTcpStreams\b", "platform.PerfTcpStreams"),
    (r"\bperfBatchSize\b", "platform.PerfBatchSize"),
    (r"\bperfPollMs\b", "platform.PerfPollMs"),
    (r"\bperfSockBuf\b", "platform.PerfSockBuf"),
    (r"\bapplyTunnelTuning\b", "platform.ApplyTunnelTuning"),
    (r"\brestoreTunnelTuning\b", "platform.RestoreTunnelTuning"),
    (r"\btuningModeLabel\b", "platform.TuningModeLabel"),
    (r"\bgetBuf\b", "platform.GetBuf"),
    (r"\bputBuf\b", "platform.PutBuf"),
    (r"\bgetICMPFrame\b", "platform.GetICMPFrame"),
    (r"\bputICMPFrame\b", "platform.PutICMPFrame"),
    (r"\bbuildICMPFrame\b", "platform.BuildICMPFrame"),
    (r"\bparseIcmpWirePacket\b", "platform.ParseIcmpWirePacket"),
    (r"\btuneUDPConn\b", "platform.TuneUDPConn"),
    (r"\btuneRawSock\b", "platform.TuneRawSock"),
    (r"\btuneTCPConn\b", "platform.TuneTCPConn"),
    (r"\bconnectUDP\b", "platform.ConnectUDP"),
    (r"\bopenRawICMP\b", "platform.OpenRawICMP"),
    (r"\bcloseFDs\b", "platform.CloseFDs"),
    (r"\bnewTunPoller\b", "platform.NewTunPoller"),
    (r"\bnewTunPollerH\b", "platform.NewTunPollerH"),
    (r"\bloadModules\b", "platform.LoadModules"),
    (r"\bsetupBonding\b", "platform.SetupBonding"),
    (r"\baddMSS\b", "platform.AddMSS"),
    (r"\bdelMSS\b", "platform.DelMSS"),
    (r"\biptablesEnsure\b", "platform.IptablesEnsure"),
    (r"\bnlCreate\b", "platform.NlCreate"),
    (r"\bnlUp\b", "platform.NlUp"),
    (r"\bnlDown\b", "platform.NlDown"),
    (r"\bnlSetMaster\b", "platform.NlSetMaster"),
    (r"\bnlRouteAdd\b", "platform.NlRouteAdd"),
    (r"\bnlRouteECMP\b", "platform.NlRouteECMP"),
    (r"\bnlRouteECMPWithSrc\b", "platform.NlRouteECMPWithSrc"),
    (r"\bnlRouteDelAll\b", "platform.NlRouteDelAll"),
    (r"\bnlRouteDel\b", "platform.NlRouteDel"),
    (r"\bnlSysctl\b", "platform.NlSysctl"),
    (r"\brun\b", "platform.Run"),
    (r"\brunOut\b", "platform.RunOut"),
    (r"\btry\b", "platform.Try"),
    (r"\bopenvpnUseDCO\b", "platform.OpenvpnUseDCO"),
    (r"\bwireSpoofFrom\b", "wire.WireSpoofFrom"),
    (r"\bwireSpoofEnabled\b", "wire.WireSpoofEnabled"),
    (r"\blogWireSpoof\b", "wire.LogWireSpoof"),
    (r"\bwarnWireSpoofPrereqs\b", "wire.WarnWireSpoofPrereqs"),
    (r"\bwireTCPDoneExtra\b", "wire.WireTCPDoneExtra"),
    (r"\bapplyKernelMangle\b", "wire.ApplyKernelMangle"),
    (r"\bkernelTunnelWireUp\b", "wire.KernelTunnelWireUp"),
    (r"\bkernelTunnelWireDown\b", "wire.KernelTunnelWireDown"),
    (r"\btcpTunnelWireUp\b", "wire.TcpTunnelWireUp"),
    (r"\btcpTunnelWireDown\b", "wire.TcpTunnelWireDown"),
    (r"\bdialTCPWire\b", "wire.DialTCPWire"),
    (r"\blistenTCPWire\b", "wire.ListenTCPWire"),
    (r"\btcpWireKernelUp\b", "wire.TcpWireKernelUp"),
    (r"\btcpWireKernelDown\b", "wire.TcpWireKernelDown"),
    (r"\bnoteWireTxErr\b", "wire.NoteWireTxErr"),
    (r"\bacceptWirePeer\b", "wire.AcceptWirePeer"),
    (r"\bevalWirePeer\b", "wire.EvalWirePeer"),
    (r"\brememberPeerRoute\b", "wire.RememberPeerRoute"),
    (r"\bbuildIPv4Header\b", "wire.BuildIPv4Header"),
    (r"\bparseWireInner\b", "wire.ParseWireInner"),
    (r"\bparseIPv4Payload\b", "wire.ParseIPv4Payload"),
    (r"\bwireSpoof\b", "wire.WireSpoof"),
]

PLATFORM_EXPORTS = [
    ("maxPerfQueues", "MaxPerfQueues"),
    ("maxPerfBatch", "MaxPerfBatch"),
    ("getBuf", "GetBuf"),
    ("putBuf", "PutBuf"),
    ("getICMPFrame", "GetICMPFrame"),
    ("putICMPFrame", "PutICMPFrame"),
    ("buildICMPFrame", "BuildICMPFrame"),
    ("parseIcmpWirePacket", "ParseIcmpWirePacket"),
    ("hashIPPacket", "HashIPPacket"),
    ("ipTo4", "IpTo4"),
    ("stoppedFlag", "StoppedFlag"),
    ("atomicSeqDedup", "AtomicSeqDedup"),
    ("ipPktDedup", "IpPktDedup"),
    ("acquireTunnelLock", "AcquireTunnelLock"),
    ("releaseTunnelLock", "ReleaseTunnelLock"),
    ("openTunMulti", "OpenTunMulti"),
    ("openTunDev", "OpenTunDev"),
    ("applyPerfFromConfig", "ApplyPerfFromConfig"),
    ("perfSummary", "PerfSummary"),
    ("perfTunQueues", "PerfTunQueues"),
    ("perfTcpStreams", "PerfTcpStreams"),
    ("perfBatchSize", "PerfBatchSize"),
    ("perfPollMs", "PerfPollMs"),
    ("perfSockBuf", "PerfSockBuf"),
    ("applyTunnelTuning", "ApplyTunnelTuning"),
    ("restoreTunnelTuning", "RestoreTunnelTuning"),
    ("tuningModeLabel", "TuningModeLabel"),
    ("initLogger", "InitLogger"),
    ("header", "Header"),
    ("step", "Step"),
    ("logOK", "LogOK"),
    ("logWarn", "LogWarn"),
    ("logInfo", "LogInfo"),
    ("logError", "LogError"),
    ("logDebug", "LogDebug"),
    ("done", "Done"),
    ("color", "Color"),
    ("printBanner", "PrintBanner"),
    ("fmtHeartbeat", "FmtHeartbeat"),
    ("startProfileLoop", "StartProfileLoop"),
    ("parseRules", "ParseRules"),
    ("loadModules", "LoadModules"),
    ("setupBonding", "SetupBonding"),
    ("addMSS", "AddMSS"),
    ("delMSS", "DelMSS"),
    ("iptablesEnsure", "IptablesEnsure"),
    ("nlCreate", "NlCreate"),
    ("nlUp", "NlUp"),
    ("nlDown", "NlDown"),
    ("nlSetMaster", "NlSetMaster"),
    ("nlRouteAdd", "NlRouteAdd"),
    ("nlRouteECMP", "NlRouteECMP"),
    ("nlRouteECMPWithSrc", "NlRouteECMPWithSrc"),
    ("nlRouteDelAll", "NlRouteDelAll"),
    ("nlRouteDel", "NlRouteDel"),
    ("nlSysctl", "NlSysctl"),
    ("run", "Run"),
    ("runOut", "RunOut"),
    ("try", "Try"),
    ("newTunPoller", "NewTunPoller"),
    ("newTunPollerH", "NewTunPollerH"),
    ("tuneUDPConn", "TuneUDPConn"),
    ("tuneRawSock", "TuneRawSock"),
    ("tuneTCPConn", "TuneTCPConn"),
    ("connectUDP", "ConnectUDP"),
    ("openRawICMP", "OpenRawICMP"),
    ("closeFDs", "CloseFDs"),
    ("openvpnUseDCO", "OpenvpnUseDCO"),
    ("openvpnMultuWorkerDev", "OpenvpnMultuWorkerDev"),
    ("tunnelDevName", "TunnelDevName"),
    ("tunnelDevNameWithSuffix", "TunnelDevNameWithSuffix"),
    ("ApplyForward", "ApplyForward"),
    ("RemoveForward", "RemoveForward"),
]


def read(path):
    with open(path, encoding="utf-8") as f:
        return f.read()


def write(path, content):
    with open(path, "w", encoding="utf-8") as f:
        f.write(content)


def fix_pkg(content, pkg):
    return re.sub(r"^package \w+", f"package {pkg}", content, count=1, flags=re.MULTILINE)


def merge_imports(content, new_imports):
    """Add missing import paths to existing import block."""
    for imp in new_imports:
        if imp in content:
            continue
        content = re.sub(
            r"(import \(\n)",
            rf"\1\t\"{imp}\"\n",
            content,
            count=1,
        )
    return content


def capitalize_platform_exports(content):
    for low, cap in PLATFORM_EXPORTS:
        content = re.sub(rf"\bfunc {low}\b", f"func {cap}", content)
        content = re.sub(rf"\btype {low}\b", f"type {cap}", content)
        content = re.sub(rf"\bconst {low}\b", f"const {cap}", content)
    # methods on StoppedFlag etc stay same receiver name if we rename type
    content = re.sub(r"\*stoppedFlag\b", "*StoppedFlag", content)
    content = re.sub(r"\*atomicSeqDedup\b", "*AtomicSeqDedup", content)
    content = re.sub(r"\*ipPktDedup\b", "*IpPktDedup", content)
    content = re.sub(r"\bstoppedFlag\b", "StoppedFlag", content)
    content = re.sub(r"\batomicSeqDedup\b", "AtomicSeqDedup", content)
    content = re.sub(r"\bipPktDedup\b", "IpPktDedup", content)
    return content


def fix_platform_file(content):
    content = capitalize_platform_exports(content)
    content = re.sub(r"\*Config\b", "*config.Config", content)
    content = re.sub(r"\bLoggingCfg\b", "config.LoggingCfg", content)
    content = re.sub(r"\bTuningCfg\b", "config.TuningCfg", content)
    content = re.sub(r"\bForwardRule\b", "ForwardRule", content)  # keep local
    content = re.sub(r"\bTunnel\b", "core.Tunnel", content)
    content = re.sub(r"\bplainIP\(", "core.PlainIP(", content)
    content = re.sub(r"wireSpoofEnabled\(", "wire.WireSpoofEnabled(", content)
    content = re.sub(r"initProfiler\(&config\.Config\{Logging:", "initProfiler(&config.Config{Logging:", content)
    content = re.sub(r"config\.config\.Config", "config.Config", content)
    content = re.sub(r"core\.core\.Tunnel", "core.Tunnel", content)
    content = merge_imports(content, [
        "virlink/internal/config",
        "virlink/internal/core",
        "virlink/internal/wire",
    ])
    return content


def fix_wire_file(content):
    content = re.sub(r"\*Config\b", "*config.Config", content)
    content = re.sub(r"\bMangleCfg\b", "config.MangleCfg", content)
    content = re.sub(r"\bipTo4\(", "platform.IpTo4(", content)
    content = re.sub(r"\blogOK\(", "platform.LogOK(", content)
    content = re.sub(r"\blogWarn\(", "platform.LogWarn(", content)
    content = re.sub(r"\blogDebug\(", "platform.LogDebug(", content)
    content = merge_imports(content, [
        "virlink/internal/config",
        "virlink/internal/platform",
    ])
    # export wire spoof symbols
    content = re.sub(r"\bfunc wireSpoofFrom\b", "func WireSpoofFrom", content)
    content = re.sub(r"\bfunc wireSpoofEnabled\b", "func WireSpoofEnabled", content)
    content = re.sub(r"\bfunc validateMangle\b", "func ValidateMangle", content)
    content = re.sub(r"\bfunc validateWireSpoofTunnel\b", "func ValidateWireSpoofTunnel", content)
    content = re.sub(r"\bfunc logWireSpoof\b", "func LogWireSpoof", content)
    content = re.sub(r"\bfunc warnWireSpoofPrereqs\b", "func WarnWireSpoofPrereqs", content)
    content = re.sub(r"\bfunc wireTCPDoneExtra\b", "func WireTCPDoneExtra", content)
    content = re.sub(r"\bfunc noteWireTxErr\b", "func NoteWireTxErr", content)
    content = re.sub(r"\btype wireSpoof\b", "type WireSpoof", content)
    content = re.sub(r"\bwireSpoof\b", "WireSpoof", content)
    content = re.sub(r"\bfunc rememberPeerRoute\b", "func RememberPeerRoute", content)
    content = re.sub(r"\bfunc acceptWirePeer\b", "func AcceptWirePeer", content)
    content = re.sub(r"\bfunc evalWirePeer\b", "func EvalWirePeer", content)
    content = re.sub(r"\bfunc applyKernelMangle\b", "func ApplyKernelMangle", content)
    content = re.sub(r"\bfunc kernelTunnelWireUp\b", "func KernelTunnelWireUp", content)
    content = re.sub(r"\bfunc kernelTunnelWireDown\b", "func KernelTunnelWireDown", content)
    content = re.sub(r"\bfunc tcpTunnelWireUp\b", "func TcpTunnelWireUp", content)
    content = re.sub(r"\bfunc tcpTunnelWireDown\b", "func TcpTunnelWireDown", content)
    content = re.sub(r"\bfunc dialTCPWire\b", "func DialTCPWire", content)
    content = re.sub(r"\bfunc listenTCPWire\b", "func ListenTCPWire", content)
    content = re.sub(r"\bfunc tcpWireKernelUp\b", "func TcpWireKernelUp", content)
    content = re.sub(r"\bfunc tcpWireKernelDown\b", "func TcpWireKernelDown", content)
    content = re.sub(r"\bfunc buildIPv4Header\b", "func BuildIPv4Header", content)
    content = re.sub(r"\bfunc parseWireInner\b", "func ParseWireInner", content)
    content = re.sub(r"\bfunc parseIPv4Payload\b", "func ParseIPv4Payload", content)
    return content


def fix_protocol_file(content, pkg):
    # skip register.go
    for pat, sub in PROTO_REPL:
        content = re.sub(pat, sub, content)
    content = re.sub(r"config\.config\.Config", "config.Config", content)
    content = re.sub(r"platform\.platform\.", "platform.", content)
    content = merge_imports(content, [
        "virlink/internal/config",
        "virlink/internal/core",
        "virlink/internal/platform",
        "virlink/internal/wire",
    ])
    return content


def main():
    for rel, pkg in PKG_MAP.items():
        d = os.path.join(ROOT, rel)
        if not os.path.isdir(d):
            continue
        for fn in os.listdir(d):
            if not fn.endswith(".go"):
                continue
            path = os.path.join(d, fn)
            content = read(path)
            content = fix_pkg(content, pkg)
            if rel == "internal/platform" and fn not in ("validate.go",):
                content = fix_platform_file(content)
            elif rel == "internal/wire":
                content = fix_wire_file(content)
            elif rel.startswith("internal/protocol/") and fn != "register.go":
                content = fix_protocol_file(content, pkg)
            write(path, content)

    # platform devname wrappers
    devname = '''package platform

import "virlink/internal/config"

func TunnelDevName(c *config.Config, fallback string) string {
	return config.TunnelDevName(c, fallback)
}

func TunnelDevNameWithSuffix(c *config.Config, fallback, suffix string) string {
	return config.TunnelDevNameWithSuffix(c, fallback, suffix)
}

func OpenvpnMultuWorkerDev(c *config.Config, i int) string {
	return config.OpenvpnMultuWorkerDev(c, i)
}
'''
    write(os.path.join(ROOT, "internal/platform/devname.go"), devname)

    # app files
    for fn in ("cli.go", "daemon.go"):
        path = os.path.join(ROOT, "internal/app", fn)
        content = fix_pkg(read(path), "app")
        content = re.sub(r"\*Config\b", "*config.Config", content)
        content = re.sub(r"\bTunnel\b", "core.Tunnel", content)
        content = re.sub(r"\bloadConfig\b", "config.Load", content)
        content = re.sub(r"\bnewTunnel\b", "core.New", content)
        content = re.sub(r"\binitLogger\b", "platform.InitLogger", content)
        content = re.sub(r"\bcolor\(", "platform.Color(", content)
        content = re.sub(r"\bcRed\b", "platform.CRed", content)
        content = re.sub(r"\blogInfo\b", "platform.LogInfo", content)
        content = re.sub(r"\blogError\b", "platform.LogError", content)
        content = re.sub(r"\blogWarn\b", "platform.LogWarn", content)
        content = re.sub(r"\bheader\b", "platform.Header", content)
        content = re.sub(r"\bplainIP\b", "core.PlainIP", content)
        content = re.sub(r"\bForwardRule\b", "platform.ForwardRule", content)
        content = re.sub(r"\bparseRules\b", "platform.ParseRules", content)
        content = re.sub(r"\bApplyForward\b", "platform.ApplyForward", content)
        content = re.sub(r"\bRemoveForward\b", "platform.RemoveForward", content)
        content = re.sub(r"\bHealthMgr\b", "platform.HealthMgr", content)
        content = re.sub(r"\bNewHealthMgr\b", "platform.NewHealthMgr", content)
        content = re.sub(r"\bprintBanner\b", "platform.PrintBanner", content)
        content = re.sub(r"\bprintHeartbeat\b", "printHeartbeat", content)
        content = re.sub(r"\bstartProfileLoop\b", "platform.StartProfileLoop", content)
        content = re.sub(r"\bfmtHeartbeat\b", "platform.FmtHeartbeat", content)
        content = re.sub(r"\bwireLogHeartbeat\b", "wire.WireLogHeartbeat", content)
        content = re.sub(r"\bwireguardLatestHandshake\b", "wireguard.WireguardLatestHandshake", content)
        content = re.sub(r"\*Hysteria2Tunnel\b", "*hysteria2.Hysteria2Tunnel", content)
        content = re.sub(r"\*WireGuardTunnel\b", "*wireguard.WireGuardTunnel", content)
        content = re.sub(r"\*AmneziaWGTunnel\b", "*amneziawg.AmneziaWGTunnel", content)
        content = re.sub(r"\brunDaemon\b", "runDaemon", content)
        content = merge_imports(content, [
            "virlink/internal/config",
            "virlink/internal/core",
            "virlink/internal/platform",
            "virlink/internal/wire",
            "virlink/internal/protocol/amneziawg",
            "virlink/internal/protocol/hysteria2",
            "virlink/internal/protocol/wireguard",
            "_ \"virlink/internal/protocol/register\"",
        ])
        write(path, content)

    # main.go
    main_path = os.path.join(ROOT, "cmd/virlink/main.go")
    write(main_path, '''// Command virlink — Linux tunnel manager CLI entry point.
package main

import "virlink/internal/app"

func main() {
	app.Main()
}
''')

    # cli.go Main export
    cli_path = os.path.join(ROOT, "internal/app/cli.go")
    content = read(cli_path)
    content = re.sub(r"^func Main\(\)", "func Main()", content, flags=re.MULTILINE)
    content = content.replace("platform.ValidateConfig", "platform.ValidateConfig")
    if "platform.FinalizeConfig" not in content:
        content = content.replace(
            "cfg, err := config.Load(*cfgFile)",
            "cfg, err := config.Load(*cfgFile)\n\tif err == nil {\n\t\tplatform.FinalizeConfig(cfg)\n\t}",
        )
        # fix double err check - do properly
    write(cli_path, content)

    # delete virlink duplicates
    for fn in ("config.go", "tunnel.go"):
        p = os.path.join(ROOT, "internal/virlink", fn)
        if os.path.exists(p):
            os.remove(p)

    print("restructure applied")


if __name__ == "__main__":
    main()

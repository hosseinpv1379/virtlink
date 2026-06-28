// openvpnmultu_conf.go — runtime OpenVPN worker .conf generation (not stored in PKI).
package virlink

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

func openvpnMultuRuntimeDir(c *Config) string {
	return filepath.Join("/var/run/virlink", tunnelInstanceName(c))
}

func openvpnMultuWorkerConfPath(c *Config, i int) string {
	return filepath.Join(openvpnMultuRuntimeDir(c), fmt.Sprintf("w%d.conf", i))
}

// openvpnMultuMaterializeWorkers writes N worker openvpn configs under
// /var/run/virlink/{tunnelName}/ and returns that directory.
func openvpnMultuMaterializeWorkers(c *Config) (string, error) {
	pkiDir := strings.TrimSpace(c.OpenVPNMultu.PKIDir)
	if pkiDir == "" {
		return "", fmt.Errorf("[openvpnmultu] pki_dir is required")
	}
	n := c.OpenVPNMultu.Workers
	runtimeDir := openvpnMultuRuntimeDir(c)
	if err := os.RemoveAll(runtimeDir); err != nil {
		return "", fmt.Errorf("[openvpnmultu] clean runtime dir: %w", err)
	}
	if err := os.MkdirAll(runtimeDir, 0o755); err != nil {
		return "", fmt.Errorf("[openvpnmultu] runtime dir: %w", err)
	}

	tunMTU, mssfix := openvpnMultuTunMTU(c)
	peerOverlay := peerAddr(c, openvpnMultuSubnet)
	perf := openvpnMultuPerfMode(c)
	proto := c.Transport.Proto
	if proto == "" {
		proto = "udp"
	}
	basePort := c.Transport.Port
	if basePort == 0 {
		basePort = 1194
	}

	for i := 0; i < n; i++ {
		linkClient, linkServer := openvpnMultuWorkerLinkIPs(i, c.Mode)
		confPath := openvpnMultuWorkerConfPath(c, i)
		port := basePort + i
		dev := fmt.Sprintf("ovpnm-w%d", i)

		var body string
		var err error
		if c.Mode == "server" {
			body, err = openvpnMultuWriteServerConf(pkiDir, port, proto, linkClient, linkServer, dev, perf, tunMTU, mssfix)
		} else {
			remote := c.RemoteIP
			body, err = openvpnMultuWriteClientConf(pkiDir, port, proto, remote, linkClient, linkServer, dev, perf, tunMTU, mssfix)
		}
		if err != nil {
			_ = os.RemoveAll(runtimeDir)
			return "", fmt.Errorf("[openvpnmultu] worker %d: %w", i, err)
		}
		body += openvpnMultuOverlayRouteBlock(peerOverlay)
		if err := os.WriteFile(confPath, []byte(body), 0o644); err != nil {
			_ = os.RemoveAll(runtimeDir)
			return "", fmt.Errorf("[openvpnmultu] write %s: %w", confPath, err)
		}
	}
	return runtimeDir, nil
}

func openvpnMultuWorkerLinkIPs(idx int, mode string) (client, server string) {
	base := idx*4 + 1
	if mode == "client" {
		return fmt.Sprintf("10.20.55.%d", base), fmt.Sprintf("10.20.55.%d", base+1)
	}
	return fmt.Sprintf("10.20.55.%d", base+1), fmt.Sprintf("10.20.55.%d", base)
}

// openvpnMultuOverlayRouteBlock installs the overlay peer route when a worker session
// comes up. Multiple workers → multiple /32 nexthops → kernel ECMP (no upfront ECMP).
func openvpnMultuOverlayRouteBlock(peerOverlay string) string {
	return fmt.Sprintf("\n# virlink openvpnmultu — overlay peer via this worker (ECMP when all workers up)\nroute %s 255.255.255.255 vpn_gateway\n", peerOverlay)
}

func openvpnMultuPerfMode(c *Config) string {
	switch tuningMode(c) {
	case tuningResource:
		return tuningResource
	case tuningLatency:
		return tuningLatency
	case tuningFast, tuningBalanced:
		return tuningFast
	default:
		return tuningFast
	}
}

func openvpnMultuTunMTU(c *Config) (tunMTU, mssfix int) {
	proto := c.Transport.Proto
	if proto == "" {
		proto = "udp"
	}
	tunMTU, mssfix = openvpnMTUForProto(proto)
	if c.Tunnel.MTU > 0 {
		tunMTU = c.Tunnel.MTU
		if mssfix > tunMTU-40 {
			mssfix = tunMTU - 40
		}
		if mssfix < 576 {
			mssfix = 576
		}
	}
	return tunMTU, mssfix
}

func openvpnMTUForProto(proto string) (tunMTU, mssfix int) {
	if proto == "tcp" {
		return 1400, 1360
	}
	return 1472, 1432
}

func openvpnOpenvpnProto(base, role string) string {
	switch base {
	case "tcp":
		if role == "server" {
			return "tcp-server"
		}
		return "tcp-client"
	case "udp":
		return "udp"
	default:
		return base
	}
}

func openvpnMultuWriteServerConf(pkiDir string, port int, proto, clientIP, serverIP, dev, perf string, tunMTU, mssfix int) (string, error) {
	ovpnProto := openvpnOpenvpnProto(proto, "server")
	crypto, err := openvpnWriteCryptoBlock(pkiDir, "server")
	if err != nil {
		return "", err
	}
	var b strings.Builder
	fmt.Fprintf(&b, `# virlink OpenVPN multu — server worker (%s profile, %s)
port %d
proto %s
dev %s
dev-type tun
persist-key
persist-tun
ca %s
cert %s
key %s
user nobody
group nogroup
%s
tls-server
ifconfig %s %s
`, perf, proto, port, ovpnProto, dev,
		filepath.Join(pkiDir, "ca.crt"),
		filepath.Join(pkiDir, "server.crt"),
		filepath.Join(pkiDir, "server.key"),
		crypto, serverIP, clientIP)
	b.WriteString(openvpnPerfBlock(perf, proto, tunMTU, mssfix))
	if proto == "udp" {
		b.WriteString("explicit-exit-notify 1\n")
	}
	return b.String(), nil
}

func openvpnMultuWriteClientConf(pkiDir string, port int, proto, remoteIP, clientIP, serverIP, dev, perf string, tunMTU, mssfix int) (string, error) {
	ovpnProto := openvpnOpenvpnProto(proto, "client")
	crypto, err := openvpnWriteCryptoBlock(pkiDir, "client")
	if err != nil {
		return "", err
	}
	var b strings.Builder
	fmt.Fprintf(&b, `# virlink OpenVPN multu — client worker (%s profile, %s)
dev %s
dev-type tun
proto %s
remote %s %d
nobind
tls-client
connect-timeout 30
connect-retry-max 5
persist-key
persist-tun
ca %s
cert %s
key %s
%s
remote-cert-tls server
ifconfig %s %s
`, perf, proto, dev, ovpnProto, remoteIP, port,
		filepath.Join(pkiDir, "ca.crt"),
		filepath.Join(pkiDir, "client.crt"),
		filepath.Join(pkiDir, "client.key"),
		crypto, clientIP, serverIP)
	b.WriteString(openvpnPerfBlock(perf, proto, tunMTU, mssfix))
	return b.String(), nil
}

func openvpnWriteCryptoBlock(pkiDir, role string) (string, error) {
	tlsLine, err := openvpnTLSKeyDirective(pkiDir, role)
	if err != nil {
		return "", err
	}
	tcKey := filepath.Join(pkiDir, "tc.key")
	dhPem := filepath.Join(pkiDir, "dh.pem")
	var b strings.Builder
	if _, err := os.Stat(tcKey); err == nil {
		if role == "server" {
			b.WriteString("dh none\n")
		}
		fmt.Fprintf(&b, "tls-groups X25519:prime256v1\n%s\ntls-version-min 1.2\n", tlsLine)
	} else if _, err := os.Stat(dhPem); err == nil {
		if role == "server" {
			fmt.Fprintf(&b, "dh %s\n", dhPem)
		}
		fmt.Fprintf(&b, "%s\ntls-version-min 1.2\n", tlsLine)
	} else {
		return "", fmt.Errorf("incomplete PKI in %s — missing tc.key or dh.pem", pkiDir)
	}
	return b.String(), nil
}

func openvpnTLSKeyDirective(pkiDir, role string) (string, error) {
	tcKey := filepath.Join(pkiDir, "tc.key")
	taKey := filepath.Join(pkiDir, "ta.key")
	if _, err := os.Stat(tcKey); err == nil {
		return fmt.Sprintf("tls-crypt %s", tcKey), nil
	}
	if _, err := os.Stat(taKey); err == nil {
		if role == "server" {
			return fmt.Sprintf("tls-auth %s 0", taKey), nil
		}
		return fmt.Sprintf("tls-auth %s 1", taKey), nil
	}
	return "", fmt.Errorf("missing tls-crypt key (tc.key) in %s", pkiDir)
}

func openvpnPerfBlock(perf, proto string, tunMTU, mssfix int) string {
	var b strings.Builder
	fmt.Fprintf(&b, `allow-compression no
topology p2p
float
fast-io
sndbuf 0
rcvbuf 0
tun-mtu %d
mssfix %d
auth none
data-ciphers AES-128-GCM:CHACHA20-POLY1305
data-ciphers-fallback AES-128-GCM
cipher AES-128-GCM
ncp-ciphers AES-128-GCM:CHACHA20-POLY1305
`, tunMTU, mssfix)
	switch perf {
	case tuningResource:
		b.WriteString(`# virlink profile: resource — lower CPU wakeups / power
reneg-sec 86400
keepalive 60 180
verb 0
`)
	case tuningLatency:
		b.WriteString(`# virlink profile: latency — minimal delay
reneg-sec 3600
keepalive 10 60
verb 1
`)
		if proto == "tcp" {
			b.WriteString("tcp-nodelay\n")
		}
	default:
		b.WriteString(`# virlink profile: fast — max bandwidth (default)
reneg-sec 0
keepalive 20 90
verb 1
`)
		if proto == "tcp" {
			b.WriteString("tcp-nodelay\n")
		}
	}
	return b.String()
}

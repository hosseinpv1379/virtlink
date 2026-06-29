#!/usr/bin/env python3
"""One-shot restructure helper: package renames and cross-package symbol fixes."""
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


def read(path):
    with open(path, encoding="utf-8") as f:
        return f.read()


def write(path, content):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        f.write(content)


def fix_package_decl(content, pkg):
    return re.sub(r"^package\s+\w+", f"package {pkg}", content, count=1, flags=re.MULTILINE)


def ensure_import(content, imp_block):
    if imp_block in content:
        return content
    # insert after package line
    m = re.match(r"(package \w+\n\n)", content)
    if m:
        return content[: m.end()] + imp_block + "\n" + content[m.end() :]
    m = re.match(r"(package \w+\n)", content)
    if m:
        return content[: m.end()] + "\n" + imp_block + "\n" + content[m.end() :]
    return content


def replace_platform_config_types(content):
    repl = [
        (r"\*Config\b", "*config.Config"),
        (r"\bConfig\b", "config.Config"),
        (r"\bLoggingCfg\b", "config.LoggingCfg"),
        (r"\bTuningCfg\b", "config.TuningCfg"),
        (r"\bForwardCfg\b", "config.ForwardCfg"),
        (r"\bMangleCfg\b", "config.MangleCfg"),
        (r"\bTunnel\b", "core.Tunnel"),
    ]
    for pat, sub in repl:
        content = re.sub(pat, sub, content)
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
            content = fix_package_decl(content, pkg)
            write(path, content)

    # platform: config + core imports and type fixes
    plat_dir = os.path.join(ROOT, "internal/platform")
    for fn in os.listdir(plat_dir):
        if not fn.endswith(".go") or fn == "aliases.go":
            continue
        path = os.path.join(plat_dir, fn)
        content = read(path)
        content = replace_platform_config_types(content)
        content = content.replace("core.core.Tunnel", "core.Tunnel")
        content = content.replace("config.config.Config", "config.Config")
        content = content.replace("plainIP(", "core.PlainIP(")
        if "virlink/internal/config" not in content:
            content = ensure_import(
                content,
                'import (\n\t"virlink/internal/config"\n\t"virlink/internal/core"\n)',
            )
        if fn == "perf.go" and "virlink/internal/wire" not in content:
            content = content.replace(
                'import (',
                'import (\n\t"virlink/internal/wire"\n',
                1,
            )
            content = content.replace("wireSpoofEnabled(", "wire.WireSpoofEnabled(")
        write(path, content)

    print("package renames done")


if __name__ == "__main__":
    main()

================================================================================
  sepehr-sabz — تست wire IP spoof ([mangle])
================================================================================

Topology
--------
  Client (ایران)     95.38.195.35
  Server (خارج)      64.118.156.193

Wire spoof (آنچه روی wire دیده می‌شود)
------------------------------------
  Client [mangle]    srcip = 185.41.1.52    dstip = 37.152.181.38
  Server [mangle]    srcip = 37.152.181.38  dstip = 185.41.1.52

Overlay (همه تست‌ها)
--------------------
  Subnet   10.99.0.0/24
  Client   10.99.0.1
  Server   10.99.0.2

اجرا
----
  Server (64.118.156.193):
    sudo ./virlink -c configs/sepehr-sabz/server/<type>.toml

  Client (95.38.195.35):
    sudo ./virlink -c configs/sepehr-sabz/client/<type>.toml

  قطع:
    sudo ./virlink --down -c <same-config.toml>

تست
---
  از کلاینت:
    ping -c3 10.99.0.2

  روی سرور (tcpdump — src/dst spoof):
    tcpdump -ni any host 64.118.156.193 or host 95.38.195.35 -vv

پورت‌ها
-------
  gre-fou        5701
  ipip-fou       5702
  bonded         5703 + 5704
  l2tpv3         5705
  gre-fou-ipsec  5706
  udp            5720
  tcp            8443

Spoof / rp_filter (هر دو سرور — قبل از تست)
--------------------------------------------
  sysctl -w net.ipv4.conf.all.rp_filter=0
  sysctl -w net.ipv4.conf.default.rp_filter=0
  sysctl -w net.ipv4.conf.<iface>.rp_filter=0

  فایروال: UDP پورت‌های بالا + proto 47 (GRE) + 1 (ICMP) + 58 (BIP)
  بین IPهای واقعی 95.38.195.35 ↔ 64.118.156.193 باز باشد.

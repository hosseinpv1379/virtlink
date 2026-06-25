================================================================================
  virlink spooftest — تست [mangle] wire IP spoof
================================================================================

Topology
--------
  Client (ایران)     95.38.195.51
  Server (خارج)      37.221.93.111

Wire spoof (روی wire این آدرس‌ها دیده می‌شود)
--------
  Client [mangle]    srcip = 185.217.6.110   dstip = 37.152.181.38
  Server [mangle]    srcip = 37.152.181.38   dstip = 185.217.6.110

Overlay (همه تست‌ها)
--------
  Subnet   10.99.0.0/24
  Client   10.99.0.1
  Server   10.99.0.2

باینری
------
  روی هر دو سرور (linux amd64):
    curl -fsSL -o /root/virlink \
      https://github.com/hosseinpv1379/virtlink/releases/download/v2.8.4/virlink
    chmod +x /root/virlink

اجرا
----
  Server:
    sudo ./virlink -c server/<type>.toml

  Client:
    sudo ./virlink -c client/<type>.toml

  قطع:
    sudo ./virlink --down -c <same-config.toml>

تست
---
  از کلاینت:
    ping -c3 10.99.0.2

  روی سرور (tcpdump — باید src/dst spoof را ببینی):
    tcpdump -ni any host 37.221.93.111 or host 95.38.195.51 -vv

انواع پشتیبانی‌شده
------------------
  Kernel (+ nftables mangle):
    gre-fou, ipip-fou, bonded-gre-fou, gre, l2tpv3,
    gre-fou-ipsec, gre-wg, vxlan-wg

  Userspace (+ IP_HDRINCL):
    icmp, udp, bip

  بدون [mangle]:
    tcp, udp-obfs  ← در این پوشه نیست

پورت‌ها (جلوگیری از تداخل بین تست‌ها)
------------------------------------
  gre-fou        5701
  ipip-fou       5702
  bonded         5703 + 5704
  gre-fou-ipsec  5706
  l2tpv3         5705
  gre-wg         5710
  vxlan-wg       5711
  udp            5720

WireGuard (gre-wg / vxlan-wg)
-----------------------------
  ۱. روی یک ماشین:  ./virlink keygen
  ۲. کلیدها را در client/gre-wg.toml و server/gre-wg.toml (و vxlan-wg) جایگزین کن

IPsec (gre-fou-ipsec)
---------------------
  کلیدهای نمونه در فایل هست — فقط برای تست. در production عوض کن.

Firewall
--------
  UDP پورت‌های بالا + proto 47 (GRE) + 1 (ICMP) + 58 (BIP) بین دو IP واقعی باز باشد.

Spoof / rp_filter (هر دو سرور — قبل از تست)
--------------------------------------------
  sysctl -w net.ipv4.conf.all.rp_filter=0
  sysctl -w net.ipv4.conf.default.rp_filter=0
  sysctl -w net.ipv4.conf.viifbr0.rp_filter=0    # نام interface عمومی خودت

  بدون این، کرنل بسته‌های با src جعلی را drop می‌کند.

تست ICMP (مثال)
---------------
  ۱) سرور (37.221.93.111):
       ./virlink -c server/icmp.toml

  ۲) کلاینت (95.38.195.51):
       ./virlink -c client/icmp.toml

  ۳) از کلاینت:
       ping -c3 10.99.0.2

  ۴) روی سرور wire را ببین:
       tcpdump -ni viifbr0 icmp and host 95.38.195.51

  فقط سرور بدون کلاینت = ترافیک صفر (طبیعی است).

لاگ موفق
--------
  Userspace:  wire spoof enabled (userspace IP_HDRINCL)
  Kernel:     wire spoof enabled (kernel nftables mangle)

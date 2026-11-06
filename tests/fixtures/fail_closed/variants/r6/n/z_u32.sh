iptables -P FORWARD ACCEPT
iptables -A FORWARD -s 192.0.2.0/24 -d 198.51.100.0/24 -m u32 --u32 0>>22&0x3C@12>>26&0x3F=0x10 -j DROP

iptables -P FORWARD ACCEPT
iptables -A FORWARD -m iprange --src-range 192.0.2.0-192.0.2.127 -d 198.51.100.0/24 -j DROP
iptables -A FORWARD -s 192.0.2.0/24 -d 198.51.100.0/24 -j DROP

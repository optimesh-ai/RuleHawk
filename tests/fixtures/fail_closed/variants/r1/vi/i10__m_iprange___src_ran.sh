iptables -P FORWARD DROP
iptables -A FORWARD -s 192.0.2.0/24 -d 198.51.100.0/24 -m iprange --src-range 192.0.2.1-192.0.2.2 -j DROP
iptables -A FORWARD -s 192.0.2.0/24 -d 198.51.100.0/24 -j ACCEPT

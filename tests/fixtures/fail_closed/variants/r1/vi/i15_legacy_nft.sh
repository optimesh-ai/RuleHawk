iptables-legacy -P FORWARD DROP
iptables-legacy -A FORWARD -s 192.0.2.0/24 -d 198.51.100.0/24 -j DROP
iptables-nft -A FORWARD -s 192.0.2.0/24 -d 198.51.100.0/24 -j ACCEPT

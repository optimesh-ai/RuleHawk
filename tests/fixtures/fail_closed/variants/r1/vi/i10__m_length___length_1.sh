iptables -P FORWARD DROP
iptables -A FORWARD -s 192.0.2.0/24 -d 198.51.100.0/24 -m length --length 100 -j DROP
iptables -A FORWARD -s 192.0.2.0/24 -d 198.51.100.0/24 -j ACCEPT

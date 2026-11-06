iptables -P FORWARD DROP
iptables -N G
iptables -A G -s 203.0.113.0/24 -j ACCEPT
iptables -A FORWARD -s 192.0.2.0/24 -d 198.51.100.0/24 -j DROP

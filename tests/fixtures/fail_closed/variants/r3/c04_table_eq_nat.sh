iptables -P FORWARD DROP
iptables --table=nat -A PREROUTING -s 192.0.2.0/24 -d 203.0.113.5 -j DNAT --to-destination 198.51.100.5
iptables -A FORWARD -s 192.0.2.0/24 -d 198.51.100.0/24 -j DROP
iptables -A FORWARD -s 192.0.2.0/24 -d 203.0.113.0/24 -j ACCEPT

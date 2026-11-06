iptables -P FORWARD ACCEPT
iptables -A FORWARD -s 192.0.2.0/24 -d 198.51.100.0/24 -p icmp -j DROP

iptables -P INPUT DROP
iptables -P OUTPUT DROP
iptables -P FORWARD DROP
iptables -A FORWARD -s 192.0.2.0/24 -d 198.51.100.0/24 -j ACCEPT
iptables -A FORWARD -s 198.51.100.0/24 -d 192.0.2.0/24 -j ACCEPT

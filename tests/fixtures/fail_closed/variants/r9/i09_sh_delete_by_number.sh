iptables -P INPUT DROP
iptables -P OUTPUT DROP
iptables -P FORWARD DROP
iptables -A FORWARD -s 192.0.2.0/24 -j ACCEPT
iptables -D FORWARD 1
iptables -A FORWARD -s 203.0.113.0/24 -j ACCEPT

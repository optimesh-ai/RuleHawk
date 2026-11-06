iptables -P INPUT DROP
iptables -P OUTPUT DROP
iptables -P FORWARD DROP
iptables -P FORWARD ACCEPT
iptables -A FORWARD -s 203.0.113.0/24 -j ACCEPT

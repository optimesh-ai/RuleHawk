iptables -P INPUT DROP
iptables -P OUTPUT DROP
iptables -P FORWARD DROP extra
iptables -A FORWARD -s 203.0.113.0/24 -j ACCEPT

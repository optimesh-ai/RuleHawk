iptables -P INPUT DROP
iptables -P OUTPUT DROP
iptables -P FORWARD DROP
iptables -A FORWARD -s 203.0.113.0/24 -j ACCEPT
iptables -X
iptables -P FORWARD DROP
ip6tables -P FORWARD ACCEPT

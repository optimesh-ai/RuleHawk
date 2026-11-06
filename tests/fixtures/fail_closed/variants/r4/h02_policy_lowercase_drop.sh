iptables -P FORWARD drop
iptables -A FORWARD -s 203.0.113.0/24 -j ACCEPT

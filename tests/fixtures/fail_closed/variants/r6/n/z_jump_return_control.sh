iptables -P FORWARD DROP
iptables -N G
iptables -A FORWARD -j G
iptables -A G -s 192.0.2.0/24 -j RETURN
iptables -A FORWARD -s 192.0.2.0/24 -j ACCEPT

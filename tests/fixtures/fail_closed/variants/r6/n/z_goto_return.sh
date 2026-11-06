iptables -P FORWARD ACCEPT
iptables -N G
iptables -A FORWARD -g G
iptables -A FORWARD -j DROP
iptables -A G -s 192.0.2.0/24 -j RETURN

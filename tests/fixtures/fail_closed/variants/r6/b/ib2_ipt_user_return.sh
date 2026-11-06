iptables -P FORWARD ACCEPT
iptables -N U
iptables -A U -s 192.0.2.0/24 -j RETURN
iptables -A U -d 198.51.100.0/24 -j DROP
iptables -A FORWARD -j U
iptables -A FORWARD -s 192.0.2.0/24 -d 198.51.100.0/24 -j DROP

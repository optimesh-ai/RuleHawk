iptables -P FORWARD ACCEPT
iptables -N CHK
iptables -A CHK -d 198.51.100.0/24 -j RETURN
iptables -A CHK -j DROP
iptables -A FORWARD -s 192.0.2.0/24 -j CHK

iptables -P FORWARD ACCEPT
iptables -N CHK
iptables -A CHK -p tcp -j DROP
iptables -A FORWARD -s 192.0.2.0/24 -d 198.51.100.0/24 -g CHK
iptables -A FORWARD -s 192.0.2.0/24 -d 198.51.100.0/24 -j DROP

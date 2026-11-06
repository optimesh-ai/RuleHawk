iptables -P INPUT DROP
iptables -P OUTPUT DROP
iptables -P FORWARD DROP
iptables -N BLK
iptables -A BLK -s 192.0.2.0/24 -d 198.51.100.0/24 -j DROP
iptables -A FORWARD -j BLK
iptables -A FORWARD -s 192.0.2.0/24 -j ACCEPT
iptables -F BLK

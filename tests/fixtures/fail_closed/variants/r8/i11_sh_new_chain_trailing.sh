iptables -P INPUT DROP
iptables -P OUTPUT DROP
iptables -P FORWARD ACCEPT
iptables -N BLOCK extra
iptables -A BLOCK -j DROP
iptables -A FORWARD -s 192.0.2.0/24 -d 198.51.100.0/24 -j BLOCK

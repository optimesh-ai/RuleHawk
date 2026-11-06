iptables -P INPUT DROP
iptables -P OUTPUT DROP
iptables -P FORWARD DROP
iptables -A FORWARD -s 192.0.2.0/24 -d 198.51.100.0/24 -j DROP
/usr/sbin/nft add rule netdev bypass ingress ip saddr 192.0.2.0/24 fwd to eth1

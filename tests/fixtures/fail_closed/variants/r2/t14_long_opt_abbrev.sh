iptables -P FORWARD DROP
iptables --append FORWARD --sour 192.0.2.0/24 --dest 198.51.100.0/24 --jum ACCEPT
iptables -A FORWARD -s 192.0.2.0/24 -d 198.51.100.0/24 -j DROP

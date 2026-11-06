iptables -N GUARD
iptables -A GUARD -s 192.0.2.0/24 -d 198.51.100.0/24 -m comment --comment " -P FORWARD DROP" -j DROP

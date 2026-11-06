iptables -P INPUT DROP
iptables -A INPUT -s 192.0.2.0/24 -p tcp --dport 22 -j ACCEPT

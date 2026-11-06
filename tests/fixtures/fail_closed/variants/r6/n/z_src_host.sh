iptables -P FORWARD ACCEPT
iptables -A FORWARD -s 192.0.2.0/24 -d pci.example -j DROP

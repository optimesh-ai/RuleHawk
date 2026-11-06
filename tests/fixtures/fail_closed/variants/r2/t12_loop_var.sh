iptables -P FORWARD DROP
for net in 192.0.2.0/24; do
  iptables -A FORWARD -s "$net" -d 198.51.100.0/24 -j ACCEPT
done
iptables -A FORWARD -s 192.0.2.0/24 -d 198.51.100.0/24 -j DROP

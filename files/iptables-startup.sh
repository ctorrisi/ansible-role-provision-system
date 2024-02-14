#!/usr/bin/env bash

sleep 5

iptables -t mangle -A PREROUTING -i lo -j ACCEPT
iptables -t mangle -A PREROUTING -p tcp -m tcp ! --tcp-flags FIN,SYN,RST,ACK SYN -m conntrack --ctstate NEW -j DROP
iptables -t mangle -A PREROUTING -p tcp -m conntrack --ctstate NEW -m tcpmss ! --mss 536:65535 -j DROP
iptables -t mangle -A PREROUTING -p tcp -m tcp --tcp-flags FIN,SYN,RST,PSH,ACK,URG NONE -j DROP
iptables -t mangle -A PREROUTING -p tcp -m tcp --tcp-flags FIN,SYN FIN,SYN -j DROP
iptables -t mangle -A PREROUTING -p tcp -m tcp --tcp-flags SYN,RST SYN,RST -j DROP
iptables -t mangle -A PREROUTING -p tcp -m tcp --tcp-flags FIN,SYN FIN,SYN -j DROP
iptables -t mangle -A PREROUTING -p tcp -m tcp --tcp-flags FIN,RST FIN,RST -j DROP
iptables -t mangle -A PREROUTING -p tcp -m tcp --tcp-flags FIN,ACK FIN -j DROP
iptables -t mangle -A PREROUTING -p tcp -m tcp --tcp-flags ACK,URG URG -j DROP
iptables -t mangle -A PREROUTING -p tcp -m tcp --tcp-flags FIN,ACK FIN -j DROP
iptables -t mangle -A PREROUTING -p tcp -m tcp --tcp-flags PSH,ACK PSH -j DROP
iptables -t mangle -A PREROUTING -p tcp -m tcp --tcp-flags FIN,SYN,RST,PSH,ACK,URG FIN,SYN,RST,PSH,ACK,URG -j DROP
iptables -t mangle -A PREROUTING -p tcp -m tcp --tcp-flags FIN,SYN,RST,PSH,ACK,URG NONE -j DROP
iptables -t mangle -A PREROUTING -p tcp -m tcp --tcp-flags FIN,SYN,RST,PSH,ACK,URG FIN,PSH,URG -j DROP
iptables -t mangle -A PREROUTING -p tcp -m tcp --tcp-flags FIN,SYN,RST,PSH,ACK,URG FIN,SYN,PSH,URG -j DROP
iptables -t mangle -A PREROUTING -p tcp -m tcp --tcp-flags FIN,SYN,RST,PSH,ACK,URG FIN,SYN,RST,ACK,URG -j DROP
iptables -t mangle -A PREROUTING -m addrtype --dst-type BROADCAST -j DROP
iptables -t mangle -A PREROUTING -m addrtype --dst-type MULTICAST -j DROP
iptables -t mangle -A PREROUTING -m addrtype --dst-type ANYCAST -j DROP
iptables -t mangle -A PREROUTING -s 224.0.0.0/3 -j DROP
iptables -t mangle -A PREROUTING -s 127.0.0.0/8 ! -i lo -j DROP
iptables -t mangle -A PREROUTING -f -j DROP

iptables -t raw -A PREROUTING -p tcp -m tcp ! -i docker0 --tcp-flags FIN,SYN,RST,ACK SYN -j CT --notrack

if command -v docker &> /dev/null; then
  iptables -t raw -A PREROUTING -p tcp -m tcp ! -i docker0 --tcp-flags FIN,SYN,RST,ACK SYN -j CT --notrack
  iptables -A INPUT -i docker0 -j ACCEPT
else
  iptables -t raw -A PREROUTING -p tcp -m tcp --tcp-flags FIN,SYN,RST,ACK SYN -j CT --notrack
fi

LAN_CIDR=$(ip route show default 2>/dev/null | awk '/default via/ {print $3}' | awk -F'.' '{print $1"."$2".0.0/16"}')

iptables -A INPUT -s ${LAN_CIDR} -j ACCEPT
iptables -A INPUT -i lo -j ACCEPT
iptables -A INPUT -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
iptables -A INPUT -p tcp -m multiport --dports 60022,443,8443 -m conntrack --ctstate INVALID,UNTRACKED -j SYNPROXY --sack-perm --timestamp --wscale 7 --mss 1460
iptables -A INPUT -p tcp -m conntrack --ctstate INVALID -j DROP
iptables -A INPUT -p tcp -m multiport --dports 60022,443,8443 -j ACCEPT
iptables -A INPUT -j DROP
iptables -N port-scanning
iptables -A port-scanning -p tcp -m tcp --tcp-flags FIN,SYN,RST,ACK RST -m limit --limit 1/sec --limit-burst 2 -j RETURN
iptables -A port-scanning -j DROP

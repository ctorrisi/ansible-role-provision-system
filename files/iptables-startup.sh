#!/usr/bin/env bash

sleep 10

LAN_CIDR=$(ip route show default 2>/dev/null | awk '/default via/ {print $3}' | awk -F'.' '{print $1"."$2".0.0/16"}')

iptables -I INPUT 2 -s ${LAN_CIDR} -j ACCEPT

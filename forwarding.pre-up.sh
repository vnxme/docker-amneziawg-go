#!/bin/bash

FORWARDING_IPV4="$(cat /proc/sys/net/ipv4/ip_forward)"
FORWARDING_IPV6_ALL="$(cat /proc/sys/net/ipv6/conf/all/forwarding)"
FORWARDING_IPV6_DEF="$(cat /proc/sys/net/ipv6/conf/default/forwarding)"	

local F="${FORWARDING,,:-}"
if [ "${F}" == "true" ]; then
	echo 1 > /proc/sys/net/ipv4/ip_forward
	echo 1 > /proc/sys/net/ipv6/conf/all/forwarding
	echo 1 > /proc/sys/net/ipv6/conf/default/forwarding
elif [ "${F}" == "ipv4" ]; then
	echo 1 > /proc/sys/net/ipv4/ip_forward
	echo 0 > /proc/sys/net/ipv6/conf/all/forwarding
	echo 0 > /proc/sys/net/ipv6/conf/default/forwarding
elif [ "${F}" == "ipv6" ]; then
	echo 0 > /proc/sys/net/ipv4/ip_forward
	echo 1 > /proc/sys/net/ipv6/conf/all/forwarding
	echo 1 > /proc/sys/net/ipv6/conf/default/forwarding
elif [ "${F}" == "false" ]; then
	echo 0 > /proc/sys/net/ipv4/ip_forward
	echo 0 > /proc/sys/net/ipv6/conf/all/forwarding
	echo 0 > /proc/sys/net/ipv6/conf/default/forwarding
fi

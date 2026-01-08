#!/bin/bash

echo "${FORWARDING_IPV4}" > /proc/sys/net/ipv4/ip_forward
echo "${FORWARDING_IPV6_ALL}" > /proc/sys/net/ipv6/conf/all/forwarding
echo "${FORWARDING_IPV6_DEF}" > /proc/sys/net/ipv6/conf/default/forwarding

#!/bin/bash

if [ -n "${IPT4}" ]; then
	echo "${FIREWALL_IPV4_FILTER}" | ${IPT4}-restore || true
	echo "${FIREWALL_IPV4_MANGLE}" | ${IPT4}-restore || true
	echo "${FIREWALL_IPV4_NAT}" | ${IPT4}-restore || true
fi

if [ -n "${IPT6}" ]; then
	echo "${FIREWALL_IPV6_FILTER}" | ${IPT6}-restore || true
	echo "${FIREWALL_IPV6_MANGLE}" | ${IPT6}-restore || true
	echo "${FIREWALL_IPV6_NAT}" | ${IPT6}-restore || true
fi

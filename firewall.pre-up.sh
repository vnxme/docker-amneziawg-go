#!/bin/bash

local M="${MASQUERADE,,:-}"

if [ -n "$(which iptables)" ] && [ $(iptables -t filter -L 2>/dev/null 1>&2; echo $?) -eq 0 ]; then
	IPT4='iptables'
elif [ -n "$(which iptables-legacy)" ] && [ $(iptables-legacy -t filter -L 2>/dev/null 1>&2; echo $?) -eq 0 ]; then
	IPT4='iptables-legacy'
fi

if [ -n "${IPT4}" ]; then
	FIREWALL_IPV4_FILTER="$(${IPT4}-save -t filter || true)"
	FIREWALL_IPV4_MANGLE="$(${IPT4}-save -t mangle || true)"
	FIREWALL_IPV4_NAT="$(${IPT4}-save -t nat || true)"

	${IPT4} -t filter -F || true
	${IPT4} -t mangle -F || true
	${IPT4} -t nat -F || true

	if [ "${M}" == "true" ]; then
		local IFACE="$(ip route | grep default | awk '{print $5}')"
		if [ -n "${IFACE}" ]; then
			if [ -n "${PRIVATE_IPV4:-}" ]; then
				local RANGES; IFS=';' read -r -a RANGES <<< "${PRIVATE_IPV4}"
				local RANGE; for RANGE in "${RANGES[@]}"; do
					${IPT4} -t nat -A POSTROUTING -s ${RANGE} -o ${IFACE} -j MASQUERADE || true
				done
			else
				${IPT4} -t nat -A POSTROUTING -o ${IFACE} -j MASQUERADE || true
			fi
		fi
	fi
fi

if [ -n "$(which ip6tables)" ] && [ $(ip6tables -t filter -L 2>/dev/null 1>&2; echo $?) -eq 0 ]; then
	IPT6='ip6tables'
elif [ -n "$(which ip6tables-legacy)" ] && [ $(ip6tables-legacy -t filter -L 2>/dev/null 1>&2; echo $?) -eq 0 ]; then
	IPT6='ip6tables-legacy'
fi

if [ -n "${IPT6}" ]; then
	FIREWALL_IPV6_FILTER="$(${IPT6}-save -t filter || true)"
	FIREWALL_IPV6_MANGLE="$(${IPT6}-save -t mangle || true)"
	FIREWALL_IPV6_NAT="$(${IPT6}-save -t nat || true)"

	${IPT6} -t filter -F || true
	${IPT6} -t mangle -F || true
	${IPT6} -t nat -F || true

	if [ "${M}" == "true" ]; then
		local IFACE="$(ip -6 route | grep default | awk '{print $5}')"
		if [ -n "${IFACE}" ]; then
			if [ -n "${PRIVATE_IPV6:-}" ]; then
				local RANGES; IFS=';' read -r -a RANGES <<< "${PRIVATE_IPV6}"
				local RANGE; for RANGE in "${RANGES[@]}"; do
					${IPT6} -t nat -A POSTROUTING -s ${RANGE} -o ${IFACE} -j MASQUERADE || true
				done
			else
				${IPT6} -t nat -A POSTROUTING -o ${IFACE} -j MASQUERADE || true
			fi
		fi
	fi
fi

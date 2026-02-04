#!/bin/bash

# Copyright 2026 VNXME
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

ME="$(basename -- "$0")"

ARGS="$(getopt -o c:l:r: --long count:,length:,read: -- "$@")"
if [ $? -ne 0 ]; then
	exit 1
fi

eval set -- "${ARGS}"
while true; do
	case "$1" in
		-c | --count)
			COUNT="$2"
			shift 2
			;;
		-l | --length)
			LENGTH="$2"
			shift 2
			;;
		-r | --read)
			PCAP="$2"
			shift 2
			;;
		--) shift; 
			break 
			;;
	esac
done

COUNT="${COUNT:-5}"
LENGTH="${LENGTH:-1200}"
PCAP="${PCAP:-${ME%%.*}.pcap}"

if [ ! -s "${PCAP}" ]; then
	echo "${ME}: Error: File ${PCAP} is missing or empty. Exiting."
	exit 1
fi

STREAMS=()
for FAMILY in "ip" "ip6"; do
	# Strip 20-byte IPv4 header or 40-byte IPv6 header, and 8-byte UDP header
	[ "${FAMILY}" == "ip" ] && OFFSET=$(((20+8)*2)) || OFFSET=$(((40+8)*2))
	# Generate a packet filter
	FILTER="${FAMILY} and outbound and length >= ${LENGTH}"
	# Obtain a packet count
	PCOUNT="$(tcpdump -c "${COUNT}" --number -n -r "${PCAP}" "${FILTER}" 2>/dev/null | wc -l)"
	if [ "${PCOUNT}" -gt 0 ]; then
		REGEXP="^\s+0x[0-9a-f]{1,8}:((\s|[0-9a-f])+)$"
		while IFS= read -r LINE; do
			if ! echo "${LINE}" | grep -q -E "${REGEXP}"; then
				[ "${#STREAM}" -gt "${OFFSET}" ] && STREAMS+=("${STREAM:${OFFSET}}")
				STREAM=""
			else
				STREAM="${STREAM}$(echo "${LINE}" | sed -r "s/${REGEXP}/\1/g" | tr -d ' ')"
			fi
		done < <(tcpdump -c "${COUNT}" --number -n -x -r "${PCAP}" "${FILTER}" 2>/dev/null)
		# Don't forget to add the last stream
		[ "${#STREAM}" -gt "${OFFSET}" ] && STREAMS+=("${STREAM:${OFFSET}}")
		# One PCAP file shouldn't contain both IPv4 and IPv6 packets
		break
	fi
done

printf '%s\n' "${STREAMS[@]}"

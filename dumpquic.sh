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

ARGS="$(getopt -o c:d:h:i:p:r:t:u:w: --long count:,direction:,host:,interface:,port:,resolve:,timeout:,url:,write: -- "$@")"
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
		-d | --direction)
			DIRECTION="$2"
			shift 2
			;;
		-h | --host)
			HOST="$2"
			shift 2
			;;
		-i | --interface)
			IFACE="$2"
			shift 2
			;;
		-p | --port)
			PORT="$2"
			shift 2
			;;
		-r | --resolve)
			IP="$2"
			shift 2
			;;
		-t | --timeout)
			TIMEOUT="$2"
			shift 2
			;;
		-u | --url)
			URL="$2"
			shift 2
			;;
		-w | --write)
			PCAP="$2"
			shift 2
			;;
		--) shift; 
			break 
			;;
	esac
done

COUNT="${COUNT:-5}"
DIRECTION="${DIRECTION:-inout}"
HOST="${HOST:-example.com}"
IFACE="${IFACE:-any}"
PORT="${PORT:-443}"
IP="${IP:-$(getent hosts "${HOST}" | awk '{print $1}')}"
TIMEOUT="${TIMEOUT:-5}"
URL="${URL:-https://${HOST}:${PORT}/}"
PCAP="${PCAP:-${ME%%.*}.pcap}"

echo "${ME}: Info: Capturing up to ${COUNT} UDP packets from/to ${HOST} (${IP}:${PORT}) on ${IFACE} interface."

tcpdump \
	-c "${COUNT}" \
	-i "${IFACE}" \
	-Q "${DIRECTION}" \
	-w "${PCAP}" \
	"udp and host ${IP} and port ${PORT}" &>/dev/null &
TCPDUMP_PID=$!

sleep 1

echo "${ME}: Info: Sending a QUIC request for ${URL} (${IP}:${PORT}) to succeed or abort within ${TIMEOUT} seconds."

curl \
	--http3-only \
	--insecure \
	--connect-timeout "${TIMEOUT}" \
	--max-time "${TIMEOUT}" \
	--resolve "${HOST}:${PORT}:${IP}" \
	"${URL}" &>/dev/null || true

sleep 1

echo "${ME}: Info: Saved $(tcpdump -r "${PCAP}" 2>/dev/null | wc -l) packets to $(realpath "${PCAP}"). Killing tcpdump (${TCPDUMP_PID}) and exiting."

kill "${TCPDUMP_PID}" &>/dev/null || true

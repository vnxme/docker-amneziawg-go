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

# Supported environment variables:
#
# VARIABLE  # DESCRIPTION                                        # DEFAULT VALUE          #
# --------- # -------------------------------------------------- # ---------------------- #
# CONF_DIR  # the configuration directory                        # /etc/amnezia/amneziawg #
# CONF_JSON # the configuration database file                    # configure.json         #
# LOG_LEVEL # fatal, error, warn, info, debug or trace           # info                   #

# References:
# https://github.com/pirate/wireguard-docs

DNS=("1.1.1.1" "1.0.0.1" "2606:4700:4700::1111" "2606:4700:4700::1001")

CONF_DIR="${CONF_DIR:-/etc/amnezia/amneziawg}"
CONF_JSON="configure.json"
LOG_LEVEL="${LOG_LEVEL:-info}"

ME="$(basename -- "$0")"

LL_FATAL=0
LL_ERROR=1
LL_WARN=2
LL_INFO=3
LL_DEBUG=4
LL_TRACE=5

ll_strtoint() {
	case "$1" in
		trace)
			echo "${LL_TRACE}"
			;;
		debug)
			echo "${LL_DEBUG}"
			;;
		info)
			echo "${LL_INFO}"
			;;
		warn)
			echo "${LL_WARN}"
			;;
		error)
			echo "${LL_ERROR}"
			;;
		fatal)
			echo "${LL_FATAL}"
			;;
		*)
			[ -n "$2" ] && echo "$2" || echo "${LL_INFO}"
			;;
	esac
}

ll_inttostr() {
	case "$1" in
		"${LL_TRACE}")
			echo "trace"
			;;
		"${LL_DEBUG}")
			echo "debug"
			;;
		"${LL_INFO}")
			echo "info"
			;;
		"${LL_WARN}")
			echo "warn"
			;;
		"${LL_ERROR}")
			echo "error"
			;;
		"${LL_FATAL}")
			echo "fatal"
			;;
		*)
			[ -n "$2" ] && echo "$2" || echo "unknown"
	esac
}

log() {
	if [ $# -eq 2 ] && [ -n "$1" ] && [ "$1" -le "${LL_CHOSEN}" ] && [ -n "$2" ]; then
		local LEVEL
		LEVEL="$(ll_inttostr "${1}" "unknown")"

		local LINE; while IFS= read -r LINE; do
			echo "${ME}: ${LEVEL^}: ${LINE}"
		done <<< "$2"
	fi
}

log_trace() {
	log "${LL_TRACE}" "$1"
}

log_debug() {
	log "${LL_DEBUG}" "$1"
}

log_info() {
	log "${LL_INFO}" "$1"
}

log_warn() {
	log "${LL_WARN}" "$1"
}

log_error() {
	log "${LL_ERROR}" "$1"
}

log_fatal() {
	log "${LL_FATAL}" "$1"
}

# Ref: https://filipenf.github.io/2015/12/06/bash-calculating-ip-addresses/
# Receives an IPv4/mask parameter and returns the nth IPv4 in that range
get_nth_ipv4() {
	# Converts an int to an IPv4 netmask as 24 -> 255.255.255.0
	netmask() {
		local mask=$((0xffffffff << (32 - $1))); shift
		local ip n
		for n in 1 2 3 4; do
			ip=$((mask & 0xff))${ip:+.}$ip
			mask=$((mask >> 8))
		done
		echo "${ip}"
	}

	local i1 i2 i3 i4 mask m1 m2 m3 m4
	IFS=". /" read -r i1 i2 i3 i4 mask <<< "$1"
	IFS=" ." read -r m1 m2 m3 m4 <<< "$(netmask "${mask}")"
	printf "%d.%d.%d.%d\n" "$((i1 & m1))" "$((i2 & m2))" "$((i3 & m3))" "$(($2 + (i4 & m4)))"
}

# Composed by ChatGPT, to be used with caution
# Receives an IPv6/mask parameter and returns the nth IPv6 in that range
get_nth_ipv6() {
	# Usage:
	#   get_nth_ipv6 "2001:db8:abcd::1/73" 42

	local addr prefix offset=$2
	addr=${1%/*}
	prefix=${1#*/}

	########################################
	# Expand :: to full 8-hextet form
	########################################
	local left right
	if [[ $addr == *::* ]]; then
		left=${addr%%::*}
		right=${addr##*::}

		read -ra L <<< "${left//:/ }"
		read -ra R <<< "${right//:/ }"

		local missing=$((8 - ${#L[@]} - ${#R[@]}))
		addr=$(printf "%s:" "${L[@]}")
		addr+=$(printf "0:%.0s" $(seq 1 $missing))
		addr+=$(printf "%s:" "${R[@]}")
		addr=${addr%:}
	fi

	########################################
	# Parse hextets
	########################################
	local h
	IFS=":" read -ra h <<< "$addr"
	for i in {0..7}; do
		h[$i]=$((16#${h[$i]:-0}))
	done

	########################################
	# Apply prefix mask
	########################################
	local full=$((prefix / 16))
	local rem=$((prefix % 16))

	# Zero full host hextets
	for ((i=full+1; i<8; i++)); do
		h[$i]=0
	done

	# Mask partial hextet
	if (( rem > 0 && full < 8 )); then
		local mask=$((0xffff << (16 - rem) & 0xffff))
		h[$full]=$((h[$full] & mask))
	fi

	########################################
	# Add offset (128-bit carry)
	########################################
	h[7]=$((h[7] + offset))
	for ((i=7; i>0; i--)); do
		if (( h[$i] > 0xffff )); then
			h[$i]=$((h[$i] & 0xffff))
			h[$((i-1))]=$((h[$((i-1))] + 1))
		fi
	done

	########################################
	# Convert to compressed IPv6 output
	########################################
	local out longest_start=-1 longest_len=0
	local cur_start=-1 cur_len=0

	for i in {0..8}; do
		if (( i < 8 && h[$i] == 0 )); then
			(( cur_len++ ))
			(( cur_start == -1 )) && cur_start=$i
		else
			if (( cur_len > longest_len )); then
				longest_len=$cur_len
				longest_start=$cur_start
			fi
			cur_len=0
			cur_start=-1
		fi
	done

	for i in {0..7}; do
		if (( i == longest_start && longest_len > 1 )); then
			out+="::"
			i=$((i + longest_len - 1))
			continue
		fi
		[[ $out && ${out: -1} != : ]] && out+=":"
		out+=$(printf "%x" "${h[$i]}")
	done

	echo "${out/#:/::}"
}

generate_confs() {
	# Return unless the database is a valid non-empty JSON file
	local DB; DB="${CONF_DIR}/${IFACE}/${CONF_JSON}"
	if [ ! -s "${DB}" ] ||  ! jq -e . >/dev/null 2>&1 < "${DB}"; then
		return 1
	fi

	local JUNK_PACKET_COUNT
	local JUNK_PACKET_MIN_SIZE
	local JUNK_PACKET_MAX_SIZE
	local INIT_PACKET_JUNK_SIZE
	local RESPONSE_PACKET_JUNK_SIZE
	local COOKIE_REPLY_PACKET_JUNK_SIZE
	local TRANSPORT_PACKET_JUNK_SIZE
	local INIT_PACKET_MAGIC_HEADER
	local RESPONSE_PACKET_MAGIC_HEADER
	local UNDERLOAD_PACKET_MAGIC_HEADER
	local TRANSPORT_PACKET_MAGIC_HEADER
	local SPECIAL_JUNK_PACKET_1 SPECIAL_JUNK_PACKET_2 SPECIAL_JUNK_PACKET_3 SPECIAL_JUNK_PACKET_4 SPECIAL_JUNK_PACKET_5
	read -r \
		JUNK_PACKET_COUNT JUNK_PACKET_MIN_SIZE JUNK_PACKET_MAX_SIZE \
		INIT_PACKET_JUNK_SIZE RESPONSE_PACKET_JUNK_SIZE \
		COOKIE_REPLY_PACKET_JUNK_SIZE TRANSPORT_PACKET_JUNK_SIZE \
		INIT_PACKET_MAGIC_HEADER RESPONSE_PACKET_MAGIC_HEADER \
		UNDERLOAD_PACKET_MAGIC_HEADER TRANSPORT_PACKET_MAGIC_HEADER \
		SPECIAL_JUNK_PACKET_1 SPECIAL_JUNK_PACKET_2 SPECIAL_JUNK_PACKET_3 \
		SPECIAL_JUNK_PACKET_4 SPECIAL_JUNK_PACKET_5 \
		<<< "$(
			jq -r '.amnezia | [
				.Jc // 0,
				.Jmin // 8,
				.Jmax // 80,
				.S1 // 0,
				.S2 // 0,
				.S3 // 0,
				.S4 // 0,
				.H1 // 1,
				.H2 // 2,
				.H3 // 3,
				.H4 // 4,
				.I1 // "#",
				.I2 // "#",
				.I3 // "#",
				.I4 // "#",
				.I5 // "#"
				] | join(" ")' < "${DB}"
		)"

	local LOCAL_NAME
	local LOCAL_PRIVATE_KEY
	local LOCAL_PUBLIC_KEY
	local LOCAL_HOST
	local LOCAL_PORT
	local LOCAL_TABLE
	local LOCAL_KEEPALIVE
	read -r \
		LOCAL_NAME LOCAL_PRIVATE_KEY LOCAL_PUBLIC_KEY LOCAL_HOST LOCAL_PORT LOCAL_TABLE LOCAL_KEEPALIVE \
		<<< "$(
			jq -r '.peers."1" | [
				.Name // "peer1",
				.PrivateKey // "#",
				.PublicKey // "#",
				.Host // "localhost",
				.ListenPort // 0,
				.Table // "auto",
				.PersistentKeepalive // 0
				] | join(" ")' < "${DB}"
		)"

	if [ "${LOCAL_PRIVATE_KEY}" == "#" ] || [ "${LOCAL_PUBLIC_KEY}" == "#" ] || [ "${LOCAL_PORT}" -eq 0 ]; then
		return 1
	fi

	local LOCAL_ADDR=(); readarray -t LOCAL_ADDR < <(jq -r '.peers."1".Address // [] | join("\n")' < "${DB}" | grep -v '^$')
	local LOCAL_IPS=(); readarray -t LOCAL_IPS < <(jq -r '.peers."1".AllowedIPs // [] | join("\n")' < "${DB}" | grep -v '^$')
	local LOCAL_FW1=(); readarray -t LOCAL_FW1 < <(jq -r '.peers."1".PreUp // [] | join("\n")' < "${DB}" | grep -v '^$')
	local LOCAL_FW2=(); readarray -t LOCAL_FW2 < <(jq -r '.peers."1".PostUp // [] | join("\n")' < "${DB}" | grep -v '^$')
	local LOCAL_FW3=(); readarray -t LOCAL_FW3 < <(jq -r '.peers."1".PreDown // [] | join("\n")' < "${DB}" | grep -v '^$')
	local LOCAL_FW4=(); readarray -t LOCAL_FW4 < <(jq -r '.peers."1".PostDown // [] | join("\n")' < "${DB}" | grep -v '^$')

	local LOCAL_FILE; LOCAL_FILE="${CONF_DIR}/${IFACE}.conf"

	# Ref: https://github.com/amnezia-vpn/amnezia-client/blob/4.8.12.9/client/server_scripts/awg/configure_container.sh
	cat <<-EOF | sed '/^#.*=$/d' > "${LOCAL_FILE}"
	[Interface]
	# Host = ${LOCAL_HOST}
	$([ "${LOCAL_PORT}" -gt 0 ] && echo "ListenPort = ${LOCAL_PORT}" || echo "# ListenPort =")
	PrivateKey = ${LOCAL_PRIVATE_KEY}
	Address = $(printf "%s, " "${LOCAL_ADDR[@]}" | sed 's/, $//')
	Table = ${LOCAL_TABLE}
	Jc = ${JUNK_PACKET_COUNT}
	Jmin = ${JUNK_PACKET_MIN_SIZE}
	Jmax = ${JUNK_PACKET_MAX_SIZE}
	S1 = ${INIT_PACKET_JUNK_SIZE}
	S2 = ${RESPONSE_PACKET_JUNK_SIZE}
	S3 = ${COOKIE_REPLY_PACKET_JUNK_SIZE}
	S4 = ${TRANSPORT_PACKET_JUNK_SIZE}
	H1 = ${INIT_PACKET_MAGIC_HEADER}
	H2 = ${RESPONSE_PACKET_MAGIC_HEADER}
	H3 = ${UNDERLOAD_PACKET_MAGIC_HEADER}
	H4 = ${TRANSPORT_PACKET_MAGIC_HEADER}
	$([ "${SPECIAL_JUNK_PACKET_1}" != "#" ] && echo "I1 = ${SPECIAL_JUNK_PACKET_1}" || echo "# I1 =")
	$([ "${SPECIAL_JUNK_PACKET_2}" != "#" ] && echo "I2 = ${SPECIAL_JUNK_PACKET_2}" || echo "# I2 =")
	$([ "${SPECIAL_JUNK_PACKET_3}" != "#" ] && echo "I3 = ${SPECIAL_JUNK_PACKET_3}" || echo "# I3 =")
	$([ "${SPECIAL_JUNK_PACKET_4}" != "#" ] && echo "I4 = ${SPECIAL_JUNK_PACKET_4}" || echo "# I4 =")
	$([ "${SPECIAL_JUNK_PACKET_5}" != "#" ] && echo "I5 = ${SPECIAL_JUNK_PACKET_5}" || echo "# I5 =")
	$([ "${#LOCAL_FW1[@]}" -gt 0 ] && printf "PreUp = %s\n" "${LOCAL_FW1[@]}" | sed 's/\n$//' || echo "# PreUp =")
	$([ "${#LOCAL_FW2[@]}" -gt 0 ] && printf "PostUp = %s\n" "${LOCAL_FW2[@]}" | sed 's/\n$//' || echo "# PostUp =")
	$([ "${#LOCAL_FW3[@]}" -gt 0 ] && printf "PreDown = %s\n" "${LOCAL_FW3[@]}" | sed 's/\n$//' || echo "# PreDown =")
	$([ "${#LOCAL_FW4[@]}" -gt 0 ] && printf "PostDown = %s\n" "${LOCAL_FW4[@]}" | sed 's/\n$//' || echo "# PostDown =")
	EOF

	local REMOTE_NAME
	local REMOTE_PRIVATE_KEY
	local REMOTE_PUBLIC_KEY
	local REMOTE_PRESHARED_KEY
	local REMOTE_HOST
	local REMOTE_PORT
	local REMOTE_TABLE
	local REMOTE_KEEPALIVE
	local REMOTE_ADDR=()
	local REMOTE_IPS=()
	local REMOTE_DNS=()
	local REMOTE_FW1=()
	local REMOTE_FW2=()
	local REMOTE_FW3=()
	local REMOTE_FW4=()
	local REMOTE_JUNK=()
	local REMOTE_JUNK_PACKET_1 REMOTE_JUNK_PACKET_2 REMOTE_JUNK_PACKET_3 REMOTE_JUNK_PACKET_4 REMOTE_JUNK_PACKET_5
	local REMOTE_FILE
	local IDS=(); readarray -t IDS < <(jq -r '.peers | del(."1") | keys[]' < "${DB}" | grep -v '^$')
	local ID; for ID in "${IDS[@]}"; do
		read -r \
			REMOTE_NAME REMOTE_PRIVATE_KEY REMOTE_PUBLIC_KEY REMOTE_PRESHARED_KEY REMOTE_HOST REMOTE_PORT REMOTE_TABLE REMOTE_KEEPALIVE \
			<<< "$(
				jq -r --arg id "${ID}" '.peers."\($id)" | [
					.Name // "peer\($id)",
					.PrivateKey // "",
					.PublicKey // "",
					.PresharedKey // "",
					.Host // "#",
					.ListenPort // 0,
					.Table // "auto",
					.PersistentKeepalive // 0
					] | join(" ")' < "${DB}"
			)"

		readarray -t REMOTE_ADDR < <(jq -r --arg id "${ID}" '.peers."\($id)".Address // [] | join("\n")' < "${DB}" | grep -v '^$')
		readarray -t REMOTE_IPS < <(jq -r --arg id "${ID}" '.peers."\($id)".AllowedIPs // [] | join("\n")' < "${DB}" | grep -v '^$')
		readarray -t REMOTE_DNS < <(jq -r --arg id "${ID}" '.peers."\($id)".DNS // [] | join("\n")' < "${DB}" | grep -v '^$')
		readarray -t REMOTE_FW1 < <(jq -r --arg id "${ID}" '.peers."\($id)".PreUp // [] | join("\n")' < "${DB}" | grep -v '^$')
		readarray -t REMOTE_FW2 < <(jq -r --arg id "${ID}" '.peers."\($id)".PostUp // [] | join("\n")' < "${DB}" | grep -v '^$')
		readarray -t REMOTE_FW3 < <(jq -r --arg id "${ID}" '.peers."\($id)".PreDown // [] | join("\n")' < "${DB}" | grep -v '^$')
		readarray -t REMOTE_FW4 < <(jq -r --arg id "${ID}" '.peers."\($id)".PostDown // [] | join("\n")' < "${DB}" | grep -v '^$')
		readarray -t REMOTE_JUNK < <(jq -r --arg id "${ID}" '.peers."\($id)".SpecialJunk // [] | join("\n")' < "${DB}" | grep -v '^$')

		if [ "${#REMOTE_JUNK[@]}" -gt 0 ]; then
			REMOTE_JUNK_PACKET_1="${REMOTE_JUNK[0]}"
			[ "${#REMOTE_JUNK[@]}" -gt 1 ] && REMOTE_JUNK_PACKET_2="${REMOTE_JUNK[1]}" || REMOTE_JUNK_PACKET_2="#"
			[ "${#REMOTE_JUNK[@]}" -gt 2 ] && REMOTE_JUNK_PACKET_3="${REMOTE_JUNK[2]}" || REMOTE_JUNK_PACKET_3="#"
			[ "${#REMOTE_JUNK[@]}" -gt 3 ] && REMOTE_JUNK_PACKET_4="${REMOTE_JUNK[3]}" || REMOTE_JUNK_PACKET_4="#"
			[ "${#REMOTE_JUNK[@]}" -gt 4 ] && REMOTE_JUNK_PACKET_5="${REMOTE_JUNK[4]}" || REMOTE_JUNK_PACKET_5="#"
		else
			REMOTE_JUNK_PACKET_1="${SPECIAL_JUNK_PACKET_1}"
			REMOTE_JUNK_PACKET_2="${SPECIAL_JUNK_PACKET_2}"
			REMOTE_JUNK_PACKET_3="${SPECIAL_JUNK_PACKET_3}"
			REMOTE_JUNK_PACKET_4="${SPECIAL_JUNK_PACKET_4}"
			REMOTE_JUNK_PACKET_5="${SPECIAL_JUNK_PACKET_5}"
		fi

		REMOTE_FILE="${CONF_DIR}/${IFACE}/${REMOTE_NAME}.conf"

		# Ref: https://github.com/amnezia-vpn/amnezia-client/blob/4.8.12.6/client/server_scripts/awg/template.conf
		cat <<-EOF | sed '/^#.*=$/d' > "${REMOTE_FILE}"
		[Interface]
		$([ "${REMOTE_PORT}" -gt 0 ] && echo "ListenPort = ${REMOTE_PORT}" || echo "# ListenPort =")
		PrivateKey = ${REMOTE_PRIVATE_KEY}
		Address = $(printf "%s, " "${REMOTE_ADDR[@]}" | sed 's/, $//')
		$([ "${#REMOTE_DNS[@]}" -gt 0 ] && echo "DNS = $(printf "%s, " "${REMOTE_DNS[@]}" | sed 's/, $//')" || echo "# DNS =")
		Table = ${REMOTE_TABLE}
		Jc = ${JUNK_PACKET_COUNT}
		Jmin = ${JUNK_PACKET_MIN_SIZE}
		Jmax = ${JUNK_PACKET_MAX_SIZE}
		S1 = ${INIT_PACKET_JUNK_SIZE}
		S2 = ${RESPONSE_PACKET_JUNK_SIZE}
		S3 = ${COOKIE_REPLY_PACKET_JUNK_SIZE}
		S4 = ${TRANSPORT_PACKET_JUNK_SIZE}
		H1 = ${INIT_PACKET_MAGIC_HEADER}
		H2 = ${RESPONSE_PACKET_MAGIC_HEADER}
		H3 = ${UNDERLOAD_PACKET_MAGIC_HEADER}
		H4 = ${TRANSPORT_PACKET_MAGIC_HEADER}
		$([ "${REMOTE_JUNK_PACKET_1}" != "#" ] && echo "I1 = ${REMOTE_JUNK_PACKET_1}" || echo "# I1 =")
		$([ "${REMOTE_JUNK_PACKET_2}" != "#" ] && echo "I2 = ${REMOTE_JUNK_PACKET_2}" || echo "# I2 =")
		$([ "${REMOTE_JUNK_PACKET_3}" != "#" ] && echo "I3 = ${REMOTE_JUNK_PACKET_3}" || echo "# I3 =")
		$([ "${REMOTE_JUNK_PACKET_4}" != "#" ] && echo "I4 = ${REMOTE_JUNK_PACKET_4}" || echo "# I4 =")
		$([ "${REMOTE_JUNK_PACKET_5}" != "#" ] && echo "I5 = ${REMOTE_JUNK_PACKET_5}" || echo "# I5 =")
		$([ "${#REMOTE_FW1[@]}" -gt 0 ] && printf "PreUp = %s\n" "${REMOTE_FW1[@]}" | sed 's/\n$//' || echo "# PreUp =")
		$([ "${#REMOTE_FW2[@]}" -gt 0 ] && printf "PostUp = %s\n" "${REMOTE_FW2[@]}" | sed 's/\n$//' || echo "# PostUp =")
		$([ "${#REMOTE_FW3[@]}" -gt 0 ] && printf "PreDown = %s\n" "${REMOTE_FW3[@]}" | sed 's/\n$//' || echo "# PreDown =")
		$([ "${#REMOTE_FW4[@]}" -gt 0 ] && printf "PostDown = %s\n" "${REMOTE_FW4[@]}" | sed 's/\n$//' || echo "# PostDown =")

		[Peer]
		# Name = ${LOCAL_NAME}
		PublicKey = ${LOCAL_PUBLIC_KEY}
		PresharedKey = ${REMOTE_PRESHARED_KEY}
		AllowedIPs = $(printf "%s, " "${LOCAL_IPS[@]}" | sed 's/, $//')
		$(if [ "${LOCAL_HOST}" != "#" ] && [ "${LOCAL_PORT}" -gt 0 ]; then echo "Endpoint = ${LOCAL_HOST}:${LOCAL_PORT}"; else echo "# Endpoint ="; fi)
		$([ "${LOCAL_KEEPALIVE}" -gt 0 ] && echo "PersistentKeepalive = ${LOCAL_KEEPALIVE}" || echo "# PersistentKeepalive =")
		EOF

		cat <<-EOF | sed '/^#.*=$/d' >> "${LOCAL_FILE}"

		[Peer]
		# Name = ${REMOTE_NAME}
		PublicKey = ${REMOTE_PUBLIC_KEY}
		PresharedKey = ${REMOTE_PRESHARED_KEY}
		AllowedIPs = $(printf "%s, " "${REMOTE_IPS[@]}" | sed 's/, $//')
		$(if [ "${REMOTE_HOST}" != "#" ] && [ "${REMOTE_PORT}" -gt 0 ]; then echo "Endpoint = ${REMOTE_HOST}:${REMOTE_PORT}"; else echo "# Endpoint ="; fi)
		$([ "${REMOTE_KEEPALIVE}" -gt 0 ] && echo "PersistentKeepalive = ${REMOTE_KEEPALIVE}" || echo "# PersistentKeepalive =")
		EOF
	done
}

local_add() {
	mkdir -p "${CONF_DIR}/${IFACE}"

	# Generate local private and public keys
	local LOCAL_PRIVATE_KEY LOCAL_PUBLIC_KEY
	LOCAL_PRIVATE_KEY="$(awg genkey)"
	LOCAL_PUBLIC_KEY="$(echo "${LOCAL_PRIVATE_KEY}" | awg pubkey)"

	# Choose a local 24-bit (for PTMP) or 30-bit (for PTP) IPv4 subnet
	# from the 192.168.0.0/16 block based on bytes [0:1] of the public key
	local LOCAL_IPV4_BYTES LOCAL_IPV4_NET LOCAL_IPV4_MASK LOCAL_IPV4_ADDR
	LOCAL_IPV4_BYTES="$(echo "${LOCAL_PUBLIC_KEY}" | base64 -d | dd bs=1 count=2 skip=0 status=none | xxd -p)"
	if [ "${TOPO}" == "ptp" ]; then
		LOCAL_IPV4_NET="192.168.$((16#${LOCAL_IPV4_BYTES:0:2})).$((0xfc & 0x${LOCAL_IPV4_BYTES:2:2}))"
		LOCAL_IPV4_MASK="30"
	else
		LOCAL_IPV4_NET="192.168.$((16#${LOCAL_IPV4_BYTES:0:2})).0"
		LOCAL_IPV4_MASK="24"
	fi
	LOCAL_IPV4_ADDR="$(get_nth_ipv4 "${LOCAL_IPV4_NET}/${LOCAL_IPV4_MASK}" 1)"

	# Choose a local 64-bit (for both PTMP and PTP) IPv6 subnet
	# from the fd00::/8 block based on bytes [1:7] of the public key
	local LOCAL_IPV6_BYTES LOCAL_IPV6_NET LOCAL_IPV6_MASK LOCAL_IPV6_ADDR
	LOCAL_IPV6_BYTES="$(echo "${LOCAL_PUBLIC_KEY}" | base64 -d | dd bs=1 count=7 skip=1 status=none | xxd -p)"
	LOCAL_IPV6_NET="fd$(printf '%x' $((0x03 & 0x${LOCAL_IPV6_BYTES:0:2}))):${LOCAL_IPV6_BYTES:2:4}:${LOCAL_IPV6_BYTES:6:4}:${LOCAL_IPV6_BYTES:10:4}::"
	LOCAL_IPV6_MASK="$((128 - (32 - LOCAL_IPV4_MASK)))" # Make IPv4 and IPv6 subnets equally sized
	LOCAL_IPV6_ADDR="$(get_nth_ipv6 "${LOCAL_IPV6_NET}/${LOCAL_IPV6_MASK}" 1)"

	# Choose a local port from the registered/user ports, skip the ports that are already in use
	local LOCAL_PORTS_IN_USE LOCAL_PORT_IN_USE LOCAL_PORT
	LOCAL_PORTS_IN_USE="$(netstat -ln --udp | tr -s ' ' | cut -d' ' -f4 | rev | cut -d':' -f1 | rev | tail +3 | sort -u)"
	while true; do
		LOCAL_PORT="$(shuf -i 1024-49151 -n 1)"
		for LOCAL_PORT_IN_USE in "${LOCAL_PORTS_IN_USE[@]}"; do
			if [ "${LOCAL_PORT_IN_USE}" == "${LOCAL_PORT}" ]; then
				continue 2
			fi
		done
		break
	done

	# Obtain a local public IPv4 via the ipify API, or get the address of the interface used for internet access
	local LOCAL_ADDR; LOCAL_ADDR="$(curl -s https://api.ipify.org)" || LOCAL_ADDR="$(ip route get "${DNS[0]}" | head -1 | awk '{print $7}')"

	# Obtain IPv4 and IPv6 default route interfaces
	local LOCAL_IPV4_IFACE; LOCAL_IPV4_IFACE="$(ip route get "${DNS[0]}" | head -1 | awk '{print $5}')"
	if [ -z "${LOCAL_IPV4_IFACE}" ] || [ -n "$(ifconfig "${LOCAL_IPV4_IFACE}" | grep 'not found')" ]; then
		LOCAL_IPV4_IFACE="eth0"
	fi
	local LOCAL_IPV6_IFACE; LOCAL_IPV6_IFACE="$(ip route get "${DNS[2]}" | head -1 | awk '{print $5}')"
	if [ -z "${LOCAL_IPV6_IFACE}" ] || [ -n "$(ifconfig "${LOCAL_IPV6_IFACE}" | grep 'not found')" ]; then
		LOCAL_IPV6_IFACE="${LOCAL_IPV4_IFACE}"
	fi

	# Choose the iptables flavour
	local IPT_MODULES_NEW IPT_MODULES_OLD
	IPT_MODULES_NEW="$(lsmod | grep -E "^nft_")"
	IPT_MODULES_OLD="$(lsmod | grep -E "^iptable_")"
	local IPT4="iptables"
	local IPT6="ip6tables"
	if [ -z "${IPT_MODULES_NEW}" ] && [ -n "${IPT_MODULES_OLD}" ]; then
		IPT4="iptables-legacy"
		IPT6="ip6tables-legacy"
	elif [ -n "${IPT_MODULES_NEW}" ] && [ -z "${IPT_MODULES_OLD}" ]; then
		IPT4="iptables-nft"
		IPT6="ip6tables-nft"
	fi

	# Refer to the following documents for the recommended values:
	# https://docs.amnezia.org/documentation/amnezia-wg/
	# https://github.com/amnezia-vpn/amneziawg-go/blob/v0.2.16/README.md
	# https://github.com/amnezia-vpn/amneziawg-linux-kernel-module/blob/v1.0.20251104/README.md

	# Jc, Jmin, Jmax
	# 0 ≤ Jc ≤ 128; recommended range is [4;12]
	# Jmin < Jmax ≤ 1280; recommended values are 8 and 80
	# Values 0,*,* ensure compliance with vanilla WireGuard implementations
	local JUNK_PACKET_COUNT; JUNK_PACKET_COUNT="$(shuf -i 4-12 -n 1)"
	local JUNK_PACKET_MIN_SIZE="8"
	local JUNK_PACKET_MAX_SIZE="80"

	# S1, S2, S3, S4
	# 0 ≤ S1 ≤ 1132 (1280 - 148 = 1132); recommended range is [15; 150]
	# 0 ≤ S2 ≤ 1188 (1280 -  92 = 1188); recommended range is [15; 150]
	# 0 ≤ S3 ≤ 1216 (1280 -  64 = 1216); recommended range is [15; 150]
	# S2 + (148 - 92) ≠ S1; S3 + (92 - 64) ≠ S2; S3 + (148 - 64) ≠ S1
	# Values 0,0,0,0 ensure compliance with vanilla WireGuard implementations
	local JUNK_SIZES=()
	local JUNK_SIZE
	while [ "${#JUNK_SIZES[@]}" -lt 3 ]; do
		JUNK_SIZE="$(shuf -i 15-150 -n 1)"
		if [ "${#JUNK_SIZES[@]}" -eq 1 ]; then
			if [ "$(( JUNK_SIZE + 56 ))" -eq "${JUNK_SIZES[0]}" ]; then
				continue
			fi
		elif [ "${#JUNK_SIZES[@]}" -eq 2 ]; then
			if [ "$(( JUNK_SIZE + 28 ))" -eq "${JUNK_SIZES[1]}" ]; then
				continue
			fi
			if [ "$(( JUNK_SIZE + 84 ))" -eq "${JUNK_SIZES[0]}" ]; then
				continue
			fi
		fi
		JUNK_SIZES+=("${JUNK_SIZE}")
	done
	local INIT_PACKET_JUNK_SIZE="${JUNK_SIZES[0]}" 
	local RESPONSE_PACKET_JUNK_SIZE="${JUNK_SIZES[1]}"
	local COOKIE_REPLY_PACKET_JUNK_SIZE="${JUNK_SIZES[2]}"
	local TRANSPORT_PACKET_JUNK_SIZE="0"
	
	# H1, H2, H3, H4
	# Must be a set of 4 unique numbers; recommended range is [5; 2147483647]
	# Values 1,2,3,4 ensure compliance with vanilla WireGuard implementations
	local MAGIC_HEADERS=()
	local MAGIC_HEADER
	local UINT32
	while [ "${#MAGIC_HEADERS[@]}" -lt 4 ]; do
		UINT32="$(openssl rand 4 | od -vAn -tu4 -vAn | tr -d ' ')"
		if [ "${UINT32}" -lt 5 ] || [ "${UINT32}" -gt 2147483647 ]; then
			continue
		fi
		for MAGIC_HEADER in "${MAGIC_HEADERS[@]}"; do
			if [ "${UINT32}" -eq "${MAGIC_HEADER}" ]; then
				continue 2
			fi
		done
		MAGIC_HEADERS+=("${UINT32}")
	done
	local INIT_PACKET_MAGIC_HEADER="${MAGIC_HEADERS[0]}"
	local RESPONSE_PACKET_MAGIC_HEADER="${MAGIC_HEADERS[1]}"
	local UNDERLOAD_PACKET_MAGIC_HEADER="${MAGIC_HEADERS[2]}"
	local TRANSPORT_PACKET_MAGIC_HEADER="${MAGIC_HEADERS[3]}"

	local LOCAL_IPS=()
	local LOCAL_NAME
	local LOCAL_TABLE
	if [ "${TOPO}" == "ptmp" ]; then
		LOCAL_IPS+=("0.0.0.0/0" "::/0")
		LOCAL_NAME="hub"
		LOCAL_TABLE="auto"
	elif [ "${TOPO}" == "ptp" ]; then
		LOCAL_IPS+=("0.0.0.0/1" "128.0.0.0/1" "::/1" "8000::/1")
		LOCAL_NAME="${IFACE}"
		LOCAL_TABLE="off"
	else
		LOCAL_IPS+=("${LOCAL_IPV4_ADDR}/32" "${LOCAL_IPV6_ADDR}/128")
		LOCAL_NAME="undefined"
		LOCAL_TABLE="auto"
	fi

	jq -n \
		--argjson amnezia "$(
			jq -n \
				--argjson Jc "${JUNK_PACKET_COUNT}" \
				--argjson Jmin "${JUNK_PACKET_MIN_SIZE}" \
				--argjson Jmax "${JUNK_PACKET_MAX_SIZE}" \
				--argjson S1 "${INIT_PACKET_JUNK_SIZE}" \
				--argjson S2 "${RESPONSE_PACKET_JUNK_SIZE}" \
				--argjson S3 "${COOKIE_REPLY_PACKET_JUNK_SIZE}" \
				--argjson S4 "${TRANSPORT_PACKET_JUNK_SIZE}" \
				--argjson H1 "${INIT_PACKET_MAGIC_HEADER}" \
				--argjson H2 "${RESPONSE_PACKET_MAGIC_HEADER}" \
				--argjson H3 "${UNDERLOAD_PACKET_MAGIC_HEADER}" \
				--argjson H4 "${TRANSPORT_PACKET_MAGIC_HEADER}" \
				'$ARGS.named'
		)" \
		--argjson local "$(
			jq -n \
				--arg Name "${LOCAL_NAME}" \
				--arg Host "${LOCAL_ADDR}" \
				--argjson ListenPort "${LOCAL_PORT}" \
				--arg PrivateKey "${LOCAL_PRIVATE_KEY}" \
				--arg PublicKey "${LOCAL_PUBLIC_KEY}" \
				--argjson Address "[\"${LOCAL_IPV4_ADDR}/${LOCAL_IPV4_MASK}\", \"${LOCAL_IPV6_ADDR}/${LOCAL_IPV6_MASK}\"]" \
				--argjson AllowedIPs "[$(printf "\"%s\", " "${LOCAL_IPS[@]}" | sed 's/, $//')]" \
				--arg Table "${LOCAL_TABLE}" \
				--argjson PersistentKeepalive "25" \
				--argjson PreUp "$(
					{
						cat <<-EOF
						ip -6 address add \$(printf "fe80::%04x:%04x:%04x:%04x/64" \$RANDOM \$RANDOM \$RANDOM \$RANDOM) dev %i || true
						EOF
						cat <<-EOF
						${IPT4} -t filter -A FORWARD -i %i -j ACCEPT || true
						${IPT4} -t filter -A FORWARD -o %i -j ACCEPT || true
						${IPT6} -t filter -A FORWARD -i %i -j ACCEPT || true
						${IPT6} -t filter -A FORWARD -o %i -j ACCEPT || true
						EOF
						[ "${TOPO}" == "ptmp" ] && cat <<-EOF
						${IPT4} -t nat -A POSTROUTING -s ${LOCAL_IPV4_NET}/${LOCAL_IPV4_MASK} -o ${LOCAL_IPV4_IFACE} -j MASQUERADE || true
						${IPT6} -t nat -A POSTROUTING -s ${LOCAL_IPV6_NET}/${LOCAL_IPV6_MASK} -o ${LOCAL_IPV6_IFACE} -j MASQUERADE || true
						EOF
					} | jq -R . | jq -s .
				)" \
				--argjson PostDown "$(
					{
						cat <<-EOF
						${IPT4} -t filter -D FORWARD -i %i -j ACCEPT || true
						${IPT4} -t filter -D FORWARD -o %i -j ACCEPT || true
						${IPT6} -t filter -D FORWARD -i %i -j ACCEPT || true
						${IPT6} -t filter -D FORWARD -o %i -j ACCEPT || true
						EOF
						[ "${TOPO}" == "ptmp" ] && cat <<-EOF
						${IPT4} -t nat -D POSTROUTING -s ${LOCAL_IPV4_NET}/${LOCAL_IPV4_MASK} -o ${LOCAL_IPV4_IFACE} -j MASQUERADE || true
						${IPT6} -t nat -D POSTROUTING -s ${LOCAL_IPV6_NET}/${LOCAL_IPV6_MASK} -o ${LOCAL_IPV6_IFACE} -j MASQUERADE || true
						EOF
					} | jq -R . | jq -s .
				)" \
				'$ARGS.named'
		)" \
		'{
			"amnezia": $amnezia,
			"peers": {"1": $local},
		}' > "${CONF_DIR}/${IFACE}/${CONF_JSON}"
}

local_del() {
	rm -f -- "${CONF_DIR}/${IFACE}.conf" && rm -rf -- "${CONF_DIR}/${IFACE}"
}

local_mod_remote_add() {
	# Return unless the database is a valid non-empty JSON file
	local DB; DB="${CONF_DIR}/${IFACE}/${CONF_JSON}"
	if [ ! -s "${DB}" ] ||  ! jq -e . >/dev/null 2>&1 < "${DB}"; then
		return 1
	fi

	local ID; ID="$(jq -r '.peers // {"1":{}} | keys | map(tonumber? // .) | max' < "${DB}")"; ID="$((ID+1))"
	if [ "${TOPO}" == "ptp" ] && [ "${ID}" -gt 2 ]; then
		return 1
	fi

	local LOCAL_ADDR=(); readarray -t LOCAL_ADDR < <(jq -r '.peers."1".Address // [] | join("\n")' < "${DB}" | grep -v '^$')
	local REMOTE_ADDR=()
	local REMOTE_IPS=(); [ "${TOPO}" == "ptp" ] && REMOTE_IPS+=("0.0.0.0/1" "128.0.0.0/1" "::/1" "8000::/1")
	local REMOTE_DNS=(); [ "${TOPO}" == "ptmp" ] && REMOTE_DNS+=("${DNS[@]}")
	local REMOTE_TABLE; [ "${TOPO}" == "ptp" ] && REMOTE_TABLE="off" || REMOTE_TABLE="auto"
	local ADDR CIDR MASK; for CIDR in "${LOCAL_ADDR[@]}"; do
		MASK="${CIDR##*/}"; [ -z "${MASK}" ] && continue
		if [[ "${CIDR}" == *":"* ]]; then
			ADDR="$(get_nth_ipv6 "${CIDR}" "${ID}")"
			[ "${TOPO}" == "ptmp" ] && REMOTE_IPS+=("${ADDR}/128")
		else
			ADDR="$(get_nth_ipv4 "${CIDR}" "${ID}")"
			[ "${TOPO}" == "ptmp" ] && REMOTE_IPS+=("${ADDR}/32")
		fi
		REMOTE_ADDR+=("${ADDR}/${MASK}")
	done

	# Generate remote private and public keys and a preshared key
	local REMOTE_PRIVATE_KEY REMOTE_PUBLIC_KEY REMOTE_PRESHARED_KEY
	REMOTE_PRIVATE_KEY="$(awg genkey)"
	REMOTE_PUBLIC_KEY="$(echo "${REMOTE_PRIVATE_KEY}" | awg pubkey)"
	REMOTE_PRESHARED_KEY="$(awg genpsk)"

	# Obtain the endpoint host:port combination
	local LOCAL_HOST
	local LOCAL_PORT
	read -r \
		LOCAL_HOST LOCAL_PORT \
		<<< "$(
			jq -r '.peers."1" | [
				.Host // "#",
				.ListenPort // 0
				] | join(" ")' < "${DB}"
		)"
	[ "${LOCAL_HOST}" == "#" ] && LOCAL_HOST="cdn.$(printf '%04x' ${RANDOM} ${RANDOM}).com"
	[ "${LOCAL_PORT}" -eq 0 ] && LOCAL_PORT="443"

	# Generate up to 5 unique junk packets emulating QUIC
	local SPECIAL_JUNK_PACKETS=()
	local PCAP; PCAP="$(mktemp)"
	if [ -f "${PCAP}" ]; then
		local OUT RES
		OUT="$(/bin/bash -- /app/dumpquic.sh -c 5 -d out -h "${LOCAL_HOST}" -p "${LOCAL_PORT}" -r 0.0.0.1 -t 5 -w "${PCAP}" 2>&1)"
		RES=$?
		log_trace "${OUT}"
		log_trace "Command \`/bin/bash -- /app/dumpquic.sh -c 5 -d out -h \"${LOCAL_HOST}\" -p \"${LOCAL_PORT}\" -r 0.0.0.1 -t 5 -w \"${PCAP}\" 2>&1\` exited with status code ${RES}."

		if [ "${RES}" -eq 0 ]; then
			OUT="$(/bin/bash -- /app/makejunk.sh -c 5 -l 1200 -r "${PCAP}" 2>&1)"
			RES=$?
			log_trace "${OUT}"
			log_trace "Command \`/bin/bash -- /app/makejunk.sh -c 5 -l 1200 -r \"${PCAP}\" 2>&1\` exited with status code ${RES}."

			if [ "${RES}" -eq 0 ] && [ "${#OUT}" -gt 0 ]; then
				local LINE; while IFS= read -r LINE; do
					SPECIAL_JUNK_PACKETS+=("<b 0x${LINE}>")
				done <<< "${OUT}"
			fi
		fi

		rm -- "${PCAP}" &>/dev/null ||  true
	fi

	jq \
		--arg id "${ID}" \
		--argjson remote "$(
			jq -n \
				--arg Name "${REMOTE_NAME}" \
				--arg PrivateKey "${REMOTE_PRIVATE_KEY}" \
				--arg PublicKey "${REMOTE_PUBLIC_KEY}" \
				--arg PresharedKey "${REMOTE_PRESHARED_KEY}" \
				--argjson Address "[$(printf "\"%s\", " "${REMOTE_ADDR[@]}" | sed 's/, $//')]" \
				--argjson AllowedIPs "[$(printf "\"%s\", " "${REMOTE_IPS[@]}" | sed 's/, $//')]" \
				--argjson DNS "[$(printf "\"%s\", " "${REMOTE_DNS[@]}" | sed 's/, $//')]" \
				--arg Table "${REMOTE_TABLE}" \
				--argjson PreUp "$(
					{
						[ "${TOPO}" == "ptp" ] && cat <<-EOF
						ip -6 address add \$(printf "fe80::%04x:%04x:%04x:%04x/64" \$RANDOM \$RANDOM \$RANDOM \$RANDOM) dev %i || true
						EOF
						[ "${TOPO}" == "ptp" ] && cat <<-EOF
						${IPT4} -t filter -A FORWARD -i %i -j ACCEPT || true
						${IPT4} -t filter -A FORWARD -o %i -j ACCEPT || true
						${IPT6} -t filter -A FORWARD -i %i -j ACCEPT || true
						${IPT6} -t filter -A FORWARD -o %i -j ACCEPT || true
						EOF
					} | jq -R . | jq -s .
				)" \
				--argjson PostDown "$(
					{
						[ "${TOPO}" == "ptp" ] && cat <<-EOF
						${IPT4} -t filter -D FORWARD -i %i -j ACCEPT || true
						${IPT4} -t filter -D FORWARD -o %i -j ACCEPT || true
						${IPT6} -t filter -D FORWARD -i %i -j ACCEPT || true
						${IPT6} -t filter -D FORWARD -o %i -j ACCEPT || true
						EOF
					} | jq -R . | jq -s .
				)" \
				--argjson SpecialJunk "$(
					{
						[ "${#SPECIAL_JUNK_PACKETS[@]}" -gt 0 ] && printf '%s\n' "${SPECIAL_JUNK_PACKETS[@]}"
					} | jq -R . | jq -s .
				)" \
				'$ARGS.named'
		)" \
		'.peers += {$id: $remote}' < "${DB}" > "${DB}.tmp" && mv "${DB}.tmp" "${DB}"
}

local_mod_remote_del() {
	# Return unless the database is a valid non-empty JSON file
	local DB; DB="${CONF_DIR}/${IFACE}/${CONF_JSON}"
	if [ ! -s "${DB}" ] ||  ! jq -e . >/dev/null 2>&1 < "${DB}"; then
		return 1
	fi

	rm "${CONF_DIR}/${IFACE}/${REMOTE_NAME}.conf"
	jq --arg name "${REMOTE_NAME}" 'del(.peers.[]? | select(.Name == "\($name)"))' < "${DB}" > "${DB}.tmp" && mv "${DB}.tmp" "${DB}"
}

validate_iface() {
	if [ -z "${IFACE}" ]; then
		log_error "The interface name is empty. Exiting."
		exit 1
	fi
	case "$1" in
		add)
			if [ -s "${CONF_DIR}/${IFACE}.conf" ]; then
				log_error "Found a non-empty configuration file for the given interface. Exiting."
				exit 1
			fi
			if [ -d "${CONF_DIR}/${IFACE}" ]; then
				log_error "Found a configuration directory for the given interface. Exiting."
				exit 1
			fi
			return 0
			;;

		del | mod | regen)
			if [ ! -s "${CONF_DIR}/${IFACE}.conf" ]; then
				log_error "Failed to find a non-empty configuration file for the given interface. Exiting."
				exit 1
			fi
			if [ ! -d "${CONF_DIR}/${IFACE}" ]; then
				log_error "Failed to find a configuration directory for the given interface. Exiting."
				exit 1
			fi
			return 0
			;;

		*)
			return 1
			;;
	esac
}

validate_remote_name() {
	if [ -z "${REMOTE_NAME}" ]; then
		log_error "The peer name is empty. Exiting."
		exit 1
	fi
	case "$1" in
		add)
			local COUNT; COUNT="$(
				jq --arg name "${REMOTE_NAME}" 'def count(stream): reduce stream as $i (0; .+1); count(.peers.[]? | select(.Name == "\($name)"))' < "${CONF_DIR}/${IFACE}/${CONF_JSON}"
			)"
			if [ -s "${CONF_DIR}/${IFACE}/${REMOTE_NAME}.conf" ] || [ "${COUNT}" -gt 0 ]; then
				log_error "Found a non-empty configuration entry/file for the given peer. Exiting."
				exit 1
			fi
			return 0
			;;

		del | mod)
			local COUNT; COUNT="$(
				jq --arg name "${REMOTE_NAME}" 'def count(stream): reduce stream as $i (0; .+1); count(.peers.[]? | select(.Name == "\($name)"))' < "${CONF_DIR}/${IFACE}/${CONF_JSON}"
			)"
			if [ ! -s "${CONF_DIR}/${IFACE}/${REMOTE_NAME}.conf" ] && [ "${COUNT}" -eq 0 ]; then
				log_error "Failed to find a non-empty configuration entry/file for the given peer. Exiting."
				exit 1
			fi
			return 0
			;;

		*)
			return 1
			;;
	esac
}

# Choose a log level; use LL_INFO by default
LL_CHOSEN=$(ll_strtoint "${LOG_LEVEL,,}" "${LL_INFO}")

# Parse positional arguments. Exit immidiately, if some arguments are missing
[ $# -le 2 ] && log_error "Not enough arguments. Exiting." && exit 1
case "$1" in
	s | server | ptmp | point-to-multipoint | hub | hub-and-spoke)
		shift; TOPO="ptmp"
		[ $# -le 1 ] && log_error "Not enough arguments. Exiting." && exit 1
		case "$1" in
			a | add)
				shift; IFACE="$1"; validate_iface "add" || exit 1; shift
				local_add "$@"
				generate_confs
				;;

			d | del | delete)
				shift; IFACE="$1"; validate_iface "del" || exit 1; shift
				local_del "$@"
				;;

			m | mod | modify)
				shift; IFACE="$1"; validate_iface "mod" || exit 1; shift
				case "$1" in
					a | amnezia)
						shift
						case "$1" in
							m | mod | modify)
								shift
								log_fatal "Not implemented. Exiting." && exit 1
								;;

							*)
								log_error "Invalid arguments. Exiting." && exit 1
								;;
						esac
						;;

					c | client | p | peer | s | spoke)
						shift
						case "$1" in
							a | add)
								shift; REMOTE_NAME="$1"; validate_remote_name "add" || exit 1; shift
								local_mod_remote_add "$@"
								generate_confs
								;;

							d | del | delete)
								shift; REMOTE_NAME="$1"; validate_remote_name "del" || exit 1; shift
								local_mod_remote_del "$@"
								generate_confs
								;;

							m | mod | modify)
								shift; REMOTE_NAME="$1"; validate_remote_name "mod" || exit 1; shift
								log_fatal "Not implemented. Exiting." && exit 1
								;;

							*)
								log_error "Invalid arguments. Exiting." && exit 1
								;;
						esac
						;;

					i | iface | interface)
						shift
						case "$1" in
							m | mod | modify)
								shift
								log_fatal "Not implemented. Exiting." && exit 1
								;;

							*)
								log_error "Invalid arguments. Exiting." && exit 1
								;;
						esac
						;;

					*)
						log_error "Invalid arguments. Exiting." && exit 1
						;;
				esac
				;;

			r | regen | regenerate)
				shift; IFACE="$1"; validate_iface "regen" || exit 1; shift
				generate_confs
				;;

			*)
				log_error "Invalid arguments. Exiting." && exit 1
				;;
		esac
		;;

	b | bridge | ptp | point-to-point)
		shift; TOPO="ptp"
		[ $# -le 1 ] && log_error "Not enough arguments. Exiting." && exit 1
		case "$1" in
			a | add)
				shift; IFACE="$1"; validate_iface "add" || exit 1; shift
				local_add "$@"
				generate_confs
				;;

			d | del | delete)
				shift; IFACE="$1"; validate_iface "del" || exit 1; shift
				local_del "$@"
				;;

			m | mod | modify)
				shift; IFACE="$1"; validate_iface "mod" || exit 1; shift
				case "$1" in
					a | amnezia)
						shift
						case "$1" in
							m | mod | modify)
								shift
								log_fatal "Not implemented. Exiting." && exit 1
								;;

							*)
								log_error "Invalid arguments. Exiting." && exit 1
								;;
						esac
						;;

					p | peer)
						shift
						case "$1" in
							a | add)
								shift; REMOTE_NAME="$1"; validate_remote_name "add" || exit 1; shift
								local_mod_remote_add "$@"
								generate_confs
								;;

							d | del | delete)
								shift; REMOTE_NAME="$1"; validate_remote_name "del" || exit 1; shift
								local_mod_remote_del "$@"
								generate_confs
								;;

							m | mod | modify)
								shift; REMOTE_NAME="$1"; validate_remote_name "mod" || exit 1; shift
								log_fatal "Not implemented. Exiting." && exit 1
								;;

							*)
								log_error "Invalid arguments. Exiting." && exit 1
								;;
						esac
						;;

					i | iface | interface)
						shift
						case "$1" in
							m | mod | modify)
								shift
								log_fatal "Not implemented. Exiting." && exit 1
								;;

							*)
								log_error "Invalid arguments. Exiting." && exit 1
								;;
						esac
						;;

					*)
						log_error "Invalid arguments. Exiting." && exit 1
						;;
				esac
				;;

			r | regen | regenerate)
				shift; IFACE="$1"; validate_iface "regen" || exit 1; shift
				generate_confs
				;;

			*)
				log_error "Invalid arguments. Exiting." && exit 1
				;;
		esac
		;;

	*)
		log_error "Invalid arguments. Exiting." && exit 1
		;;
esac

log_info "Please restart the container to commit any changes to the tunnel configuration."
exit 0

#!/bin/bash

# Supported environment variables:
#
# VARIABLE   # DESCRIPTION                                 # DEFAULT VALUE          #
# ---------- # ------------------------------------------- # ---------------------- #
# CONFS_DEF  # the default interface name                  # wg0                    #
# CONFS_DIR  # the configuration directory                 # /etc/amnezia/amneziawg #
# CONFS_LIST # the comma-separated list of interface names # ${CONFS_DEF}           #
# HOOKS_DIR  # the pre/post-up/down hook scripts directory # ./hooks                #
#
# Note: if ${CONFS_DIR} exists and no non-empty configuration files are found in it
# according to ${CONFS_LIST}, the script runs the daemon with each non-empty *.conf
# file. The script creates a new configuration if there are no *.conf files at all.

CONFS_DEF="${CONFS_DEF:-wg0}"
CONFS_DIR="${CONFS_DIR:-/etc/amnezia/amneziawg}"
CONFS_LIST="${CONFS_LIST:-${CONFS_DEF}}"
HOOKS_DIR="${HOOKS_DIR:-./hooks}"

PIDS=()
FILES=()

hooks() {
	[ ! -d "${HOOKS_DIR}/$1" ] && mkdir -p "${HOOKS_DIR}/$1"
	local FILE; for FILE in "${HOOKS_DIR}"/"$1"/*.sh; do
		if [ -s "${FILE}" ]; then
			/bin/bash -- "${FILE}" || true
		fi
	done
}

launch() {
	# Call pre-up hooks
	hooks "pre-up"

	# Launch one or multiple tunnels
	if [ -n "$(which awg)" ] && [ -n "$(which awg-quick)" ] && [ -n "$(which amneziawg-go)" ]; then
		local CONFS; IFS=',' read -r -a CONFS <<< "${CONFS_LIST}"
		local CONF; for CONF in "${CONFS[@]}"; do
			local FILE="${CONFS_DIR}/${CONF}.conf"
			if [ -s "${FILE}" ]; then
				awg-quick down "${FILE}" || true
				awg-quick up "${FILE}" || true
				FILES+=("${FILE}")
			fi
		done

		if [ ${#FILES[@]} -eq 0 ] && [ -d "${CONFS_DIR}" ]; then
			if [ -n "$(find "${CONFS_DIR}" -maxdepth 0 -type d -empty)" ]; then
				cd -- "${CONFS_DIR}" && bash -- /app/configure.sh "${CONFS_DEF}" && cd -
			fi

			local FILE; for FILE in "${CONFS_DIR}"/*.conf; do
				if [ -s "${FILE}" ]; then
					awg-quick down "${FILE}" || true
					awg-quick up "${FILE}" || true
					FILES+=("${FILE}")
				fi
			done
		fi
	fi

	# Launch one empty process to keep this script running
	tail -f /dev/null &
	PIDS+=($!)

	# Call post-up hooks
	hooks "post-up"
}

terminate() {
	# Call pre-down hooks
	hooks "pre-down"

	# Terminate all tunnels
	local FILE; for FILE in "${FILES[@]}"; do
		awg-quick down "${FILE}" || true
	done

	# Terminate all subprocesses
	local PID; for PID in "${PIDS[@]}"; do
		kill "${PID}" 2>/dev/null || true
	done

	# Call post-down hooks
	hooks "post-down"

	# Restore firewall and forwarding
	forwarding_down
	firewall_down

	exit 0
}

# Call terminate() when SIGTERM is received
trap terminate TERM

# Call launch() with command line arguments
launch $@

# Wait for all subprocesses to exit
FAIL=0
for PID in "${PIDS[@]}"; do
	if ! wait "${PID}"; then
		FAIL=1
	fi
done
exit ${FAIL}

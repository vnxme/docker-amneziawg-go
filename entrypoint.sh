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
# CONF_DEF  # the default interface name to create and/or run    # wg0                    #
# CONF_DIR  # the configuration directory                        # /etc/amnezia/amneziawg #
# CONF_RUN  # the comma-separated list of interface names to run # ${CONF_DEF}            #
# HOOK_DIR  # the pre/post-up/down hook scripts directory        # ./hooks                #
# LOG_DIR   # the log files directory                            # /var/log/amneziawg     #
# LOG_LEVEL # fatal, error, warn, info, debug or trace           # info                   #
#
# Note: if ${CONF_DIR} exists and no non-empty configuration files are found in it
# according to ${CONF_RUN}, the script runs the daemon with each non-empty *.conf
# file. The script creates a new configuration if there are no *.conf files at all.

CONF_DEF="${CONF_DEF:-wg0}"
CONF_DIR="${CONF_DIR:-/etc/amnezia/amneziawg}"
CONF_RUN="${CONF_RUN:-${CONF_DEF}}"
HOOK_DIR="${HOOK_DIR:-./hooks}"
LOG_DIR="${LOG_DIR:-/var/log/amneziawg}"
LOG_LEVEL="${LOG_LEVEL:-info}"

ME="$(basename -- "$0")"
PIDS=()
FILES=()

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

hooks() {
	local OUT
	local RES

	if [ ! -d "${HOOK_DIR}/$1" ]; then
		log_debug "Creating the $1 hooks directory ($(realpath .)/${HOOK_DIR}/$1)."
		OUT="$(mkdir -p "${HOOK_DIR}/$1" 2>&1)"
		RES="$?"
		log_trace "${OUT}"
		log_trace "Command \`mkdir -p \"${HOOK_DIR}/$1\" 2>&1\` exited with status code ${RES}."
		if [ "${RES}" -gt 0 ]; then
			log_warn "Failed to create the $1 hooks directory ($(realpath .)/${HOOK_DIR}/$1). Skipping $1 hooks."
			return 1
		fi
	fi

	local COUNTER=0
	local FILE; for FILE in "${HOOK_DIR}"/"$1"/*.sh; do
		if [ -s "${FILE}" ]; then
			log_debug "Executing ${FILE}."
			OUT="$(/bin/bash -- "${FILE}" 2>&1)"
			RES="$?"
			log_trace "${OUT}"
			log_trace "Command \`/bin/bash -- \"${FILE}\" 2>&1\` exited with status code ${RES}."
			if [ "${RES}" -gt 0 ]; then
				log_warn "Failed to execute ${FILE}. Consider revising this script."
			fi
			((COUNTER++))
		fi
	done

	if [ "${COUNTER}" -eq 0 ]; then
		log_debug "Found no non-empty *.sh scripts in the $1 hooks directory ($(realpath .)/${HOOK_DIR}/$1)."
	fi
}

launch() {
	local LOG
	local OUT
	local RES

	log_info "Starting."
	log_debug "Machine $(uname -m). $(uname -o) $(uname -r). Alpine $(cat /etc/alpine-release 2>/dev/null || echo "unknown")."

	# Display a warning about the arguments
	if [ $# -gt 0 ]; then
		log_warn "No command line arguments are supported. Ignoring them."
	fi 

	# Apply kernel parameters
	log_debug "Applying kernel parameters."
	OUT="$(sysctl -q -p /etc/sysctl.d/*.conf /etc/sysctl.conf 2>&1)"
	RES="$?"
	log_trace "${OUT}"
	log_trace "Command \`sysctl -q -p /etc/sysctl.d/*.conf /etc/sysctl.conf 2>&1\` exited with status code ${RES}."
	if [ "${RES}" -gt 0 ]; then
		log_warn "Some kernel parameters might have been misconfigured. Consider revising /etc/sysctl.conf and /etc/sysctl.d/*.conf."
	fi

	# Call pre-up hooks
	hooks "pre-up"

	# Enable one or multiple tunnels
	if [ -z "$(which awg)" ]; then
		log_error "Failed to find the AmneziaWG tool (awg). Exiting."
		exit 1
	elif [ -z "$(which awg-quick)" ]; then
		log_error "Failed to find the AmneziaWG helper (awg-quick). Exiting."
		exit 1
	elif [ -z "$(which amneziawg-go)" ]; then
		log_error "Failed to find the AmneziaWG binary (amneziawg-go). Exiting."
		exit 1
	else
		if [ ! -d "${LOG_DIR}" ]; then
			log_debug "Creating the log files directory (${LOG_DIR})."
			OUT="$(mkdir -p "${LOG_DIR}" 2>&1)"
			RES="$?"
			log_trace "${OUT}"
			log_trace "Command \`mkdir -p \"${LOG_DIR}\" 2>&1\` exited with status code ${RES}."
			if [ "${RES}" -gt 0 ]; then
				log_error "Failed to create the log files directory (${LOG_DIR}). Exiting."
				exit 1
			fi
		fi

		local CONFS; IFS=',' read -r -a CONFS <<< "${CONF_RUN}"
		local CONF; local FILE; for CONF in "${CONFS[@]}"; do
			FILE="${CONF_DIR}/${CONF}.conf"
			if [ -s "${FILE}" ]; then
				log_debug "Enabling tunnel $(basename -- "${FILE%.*}") (${FILE})."
				LOG="${LOG_DIR}/$(basename -- "${FILE%.*}").log"
				echo "--- UP   $(date +'%Y-%m-%d %H:%M:%S') ---" >> "${LOG}"
				OUT="$(awg-quick up "${FILE}" >> "${LOG}" 2>&1)"
				RES="$?"
				log_trace "${OUT}"
				log_trace "Command \`awg-quick up \"${FILE}\" >> \"${LOG}\" 2>&1\` exited with status code ${RES}."
				if [ "${RES}" -gt 0 ]; then
					log_warn "Failed to enable tunnel $(basename -- "${FILE%.*}") (${FILE})."
				fi
				FILES+=("${FILE}")
			fi
		done

		if [ "${#FILES[@]}" -eq 0 ] && [ -d "${CONF_DIR}" ]; then
			if [ "$(find "${CONF_DIR}" -maxdepth 1 -type f -name "*.conf" ! -size 0 | wc -l)" -eq 0 ]; then
				log_debug "Generating a new configuration (${CONF_DIR}/${CONF_DEF}.conf)."
				OUT="$(cd -- "${CONF_DIR}" || exit $?; /bin/bash -- /app/configure.sh new "${CONF_DEF}" 2>&1)"
				RES="$?"
				log_trace "${OUT}"
				log_trace "Command \`cd -- \"${CONF_DIR}\" || exit \$?; /bin/bash -- /app/configure.sh new \"${CONF_DEF}\" 2>&1\` exited with status code ${RES}."
				if [ "${RES}" -gt 0 ]; then
					log_error "Failed to generate a new configuration (${CONF_DIR}/${CONF_DEF}.conf). Exiting."
					exit 1
				fi
			fi

			local FILE; for FILE in "${CONF_DIR}"/*.conf; do
				if [ -s "${FILE}" ]; then
					log_debug "Enabling tunnel $(basename -- "${FILE%.*}") (${FILE})."
					LOG="${LOG_DIR}/$(basename -- "${FILE%.*}").log"
					echo "--- UP   $(date +'%Y-%m-%d %H:%M:%S') ---" >> "${LOG}"
					OUT="$(awg-quick up "${FILE}" >> "${LOG}" 2>&1)"
					RES="$?"
					log_trace "${OUT}"
					log_trace "Command \`awg-quick up \"${FILE}\" >> \"${LOG}\" 2>&1\` exited with status code ${RES}."
					if [ "${RES}" -gt 0 ]; then
						log_warn "Failed to enable tunnel $(basename -- "${FILE%.*}") (${FILE})."
					fi
					FILES+=("${FILE}")
				fi
			done
		fi

		if [ "${#FILES[@]}" -eq 0 ]; then
			log_debug "Found no non-empty *.sh scripts in the $1 hooks directory ($(realpath .)/${HOOK_DIR}/$1)."
		fi
	fi

	# Launch one empty process to keep this script running
	tail -f /dev/null &
	local PID; PID="$!"; PIDS+=("${PID}")
	log_debug "Launched an empty process with PID ${PID} to keep this script running."

	# Call post-up hooks
	hooks "post-up"
}

terminate() {
	local LOG
	local OUT
	local RES

	# Report that the termination trap has been called
	log_info "Received a termination signal. Cleaning up."

	# Call pre-down hooks
	hooks "pre-down"

	# Terminate all tunnels
	local FILE; for FILE in "${FILES[@]}"; do
		log_debug "Disabling tunnel $(basename -- "${FILE%.*}") (${FILE})."
		LOG="${LOG_DIR}/$(basename -- "${FILE%.*}").log"
		OUT="$(awg-quick down "${FILE}" >> "${LOG}" 2>&1)"
		RES="$?"
		log_trace "${OUT}"
		log_trace "Command \`awg-quick down \"${FILE}\" >> \"${LOG}\" 2>&1\` exited with status code ${RES}."
		if [ "${RES}" -gt 0 ]; then
			log_warn "Failed to disable tunnel $(basename -- "${FILE%.*}") (${FILE})."
		fi
		echo "--- DOWN $(date +'%Y-%m-%d %H:%M:%S') ---" >> "${LOG}"
	done

	# Terminate all subprocesses
	local PID; for PID in "${PIDS[@]}"; do
		if [ -d "/proc/${PID}" ]; then
			log_debug "Terminating process ${PID} ($(cat "/proc/${PID}/comm" 2>/dev/null || echo "unknown"))."
			OUT="$(kill "${PID}" 2>&1)"
			RES="$?"
			log_trace "${OUT}"
			log_trace "Command \`kill \"${PID}\" 2>&1\` exited with status code ${RES}."
			if [ "${RES}" -gt 0 ]; then
				log_warn "Failed to terminate process ${PID} ($(cat "/proc/${PID}/comm" 2>/dev/null || echo "unknown"))."
			fi
		fi
	done

	# Call post-down hooks
	hooks "post-down"

	log_info "Exiting."
	exit 0
}

# Choose a log level; use LL_INFO by default
LL_CHOSEN=$(ll_strtoint "${LOG_LEVEL,,}" "${LL_INFO}")

# Call terminate() when SIGINT or SIGTERM is received
trap terminate INT TERM

# Call launch() with command line arguments
launch "$@"

# Wait for all subprocesses to exit
FAIL=0
for PID in "${PIDS[@]}"; do
	if ! wait "${PID}"; then
		FAIL=1
	fi
done
log_info "All subprocesses terminated. Exiting."
exit ${FAIL}

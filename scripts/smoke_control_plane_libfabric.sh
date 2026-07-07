#!/usr/bin/env bash
set -uo pipefail

DATE_TAG="${1:-$(date +%F-%H%M%S)}"
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd -- "${SCRIPT_DIR}/.." && pwd)"
LOG_DIR="${REPO_ROOT}/logs/control_plane_smoke_${DATE_TAG}"
SUMMARY_FILE="${LOG_DIR}/summary.txt"

LIBFABRIC_PREFIX="${LIBFABRIC_PREFIX:-/opt/libfabric}"
DEFAULT_TIMEOUT_MS="${DEFAULT_TIMEOUT_MS:-15000}"
PORT_WAIT_SECS="${PORT_WAIT_SECS:-10}"
CLIENT_START_DELAY_SECS="${CLIENT_START_DELAY_SECS:-1}"
BUILD_JOBS="${BUILD_JOBS:-$(nproc)}"

export FI_PROVIDER_PATH="${REPO_ROOT}/uet_provider"
export FI_PROVIDER="uet"
export LD_LIBRARY_PATH="${LIBFABRIC_PREFIX}/lib${LD_LIBRARY_PATH:+:${LD_LIBRARY_PATH}}"
export UET_PROVIDER_DEBUG="${UET_PROVIDER_DEBUG:-1}"
export UET_PROVIDER_DEBUG_VERBOSE="${UET_PROVIDER_DEBUG_VERBOSE:-1}"

mkdir -p "${LOG_DIR}"
: > "${SUMMARY_FILE}"

log() {
  echo "$*" | tee -a "${SUMMARY_FILE}"
}

start_logged_process() {
  local logfile="$1"
  shift
  (
    cd "${REPO_ROOT}"
    exec "$@"
  ) >"${logfile}" 2>&1 &
  STARTED_PID=$!
}

wait_for_udp_listener() {
  local pid="$1"
  local port="$2"
  local logfile="$3"
  local timeout_secs="$4"
  local waited=0

  while (( waited < timeout_secs * 10 )); do
    if ! kill -0 "${pid}" 2>/dev/null; then
      return 1
    fi
    if [[ -f "${logfile}" ]] && rg -q "listening on port: ${port}" "${logfile}"; then
      return 0
    fi
    sleep 0.1
    waited=$((waited + 1))
  done
  return 1
}

copy_provider_log_if_present() {
  local pid="$1"
  local dest="$2"
  local src="${REPO_ROOT}/UET_provider_${pid}.log"
  if [[ -f "${src}" ]]; then
    cp "${src}" "${dest}"
  fi
}

record_case_result() {
  local name="$1"
  local status="$2"
  local detail="$3"
  printf '%-28s %-6s %s\n' "${name}" "${status}" "${detail}" | tee -a "${SUMMARY_FILE}"
}

run_pair_case() {
  local name="$1"
  local server_port="$2"
  local client_port="$3"
  local server_ok="$4"
  local client_ok="$5"
  shift 5

  local server_cmd=()
  local client_cmd=()
  while (($#)); do
    if [[ "$1" == "--" ]]; then
      shift
      break
    fi
    server_cmd+=("$1")
    shift
  done
  while (($#)); do
    client_cmd+=("$1")
    shift
  done

  local case_dir="${LOG_DIR}/${name}"
  local server_log="${case_dir}/server.stdout.log"
  local client_log="${case_dir}/client.stdout.log"
  mkdir -p "${case_dir}"

  local server_pid
  local client_pid
  local server_rc=1
  local client_rc=1

  start_logged_process "${server_log}" "${server_cmd[@]}"
  server_pid=${STARTED_PID}
  if ! wait_for_udp_listener "${server_pid}" "${server_port}" "${server_log}" "${PORT_WAIT_SECS}"; then
    wait "${server_pid}" || true
    copy_provider_log_if_present "${server_pid}" "${case_dir}/server.provider.log"
    record_case_result "${name}" "FAIL" "server did not become ready on UDP port ${server_port}"
    return 1
  fi

  sleep "${CLIENT_START_DELAY_SECS}"
  start_logged_process "${client_log}" "${client_cmd[@]}"
  client_pid=${STARTED_PID}

  wait "${client_pid}"
  client_rc=$?
  wait "${server_pid}"
  server_rc=$?

  copy_provider_log_if_present "${server_pid}" "${case_dir}/server.provider.log"
  copy_provider_log_if_present "${client_pid}" "${case_dir}/client.provider.log"

  if [[ ${server_rc} -ne 0 || ${client_rc} -ne 0 ]]; then
    record_case_result "${name}" "FAIL" "server_rc=${server_rc} client_rc=${client_rc}"
    return 1
  fi

  if ! rg -q "${server_ok}" "${server_log}"; then
    record_case_result "${name}" "FAIL" "server output missing pattern: ${server_ok}"
    return 1
  fi
  if ! rg -q "${client_ok}" "${client_log}"; then
    record_case_result "${name}" "FAIL" "client output missing pattern: ${client_ok}"
    return 1
  fi

  record_case_result "${name}" "PASS" "server/client completed and matched expected output"
  return 0
}

run_single_case() {
  local name="$1"
  local ok_pattern="$2"
  shift 2

  local case_dir="${LOG_DIR}/${name}"
  local run_log="${case_dir}/run.stdout.log"
  mkdir -p "${case_dir}"

  local pid
  local rc=1
  start_logged_process "${run_log}" "$@"
  pid=${STARTED_PID}
  wait "${pid}"
  rc=$?
  copy_provider_log_if_present "${pid}" "${case_dir}/provider.log"

  if [[ ${rc} -ne 0 ]]; then
    record_case_result "${name}" "FAIL" "exit code ${rc}"
    return 1
  fi
  if ! rg -q "${ok_pattern}" "${run_log}"; then
    record_case_result "${name}" "FAIL" "missing pattern: ${ok_pattern}"
    return 1
  fi

  record_case_result "${name}" "PASS" "completed and matched expected output"
  return 0
}

log "[INFO] log dir: ${LOG_DIR}"
log "[INFO] building provider and libfabric control-plane tests"

if ! make -C "${REPO_ROOT}/uet_provider" -j"${BUILD_JOBS}"; then
  log "[FAIL] provider build failed"
  exit 1
fi

if ! make -C "${REPO_ROOT}/UET/src/Test" MRDescTest MRDescWriteLibfabricTest MRDescReadLibfabricTest MRRegLibfabricTest; then
  log "[FAIL] libfabric control-plane test build failed"
  exit 1
fi

failures=0

run_pair_case \
  "MRDescTest" 4100 4101 "MRDesc sent, ack=OK" "MRDesc received:" \
  "${REPO_ROOT}/UET/src/Test/MRDescTest" --mode server --local-port 4100 --peer-port 4101 --timeout-ms "${DEFAULT_TIMEOUT_MS}" \
  -- \
  "${REPO_ROOT}/UET/src/Test/MRDescTest" --mode client --local-port 4101 --peer-port 4100 --timeout-ms "${DEFAULT_TIMEOUT_MS}" \
  || failures=$((failures + 1))

run_pair_case \
  "MRDescWriteLibfabricTest" 4200 4201 "MRDescWriteLibfabric server PASS" "MRDescWriteLibfabric client PASS" \
  "${REPO_ROOT}/UET/src/Test/MRDescWriteLibfabricTest" --mode server --local-port 4200 --peer-port 4201 --timeout-ms "${DEFAULT_TIMEOUT_MS}" --clients 1 \
  -- \
  "${REPO_ROOT}/UET/src/Test/MRDescWriteLibfabricTest" --mode client --local-port 4201 --peer-port 4200 --timeout-ms "${DEFAULT_TIMEOUT_MS}" --clients 1 --client-id 0 \
  || failures=$((failures + 1))

run_pair_case \
  "MRDescReadLibfabricTest" 4300 4301 "MRDescReadLibfabric server PASS" "MRDescReadLibfabric client PASS" \
  "${REPO_ROOT}/UET/src/Test/MRDescReadLibfabricTest" --mode server --local-port 4300 --peer-port 4301 --timeout-ms "${DEFAULT_TIMEOUT_MS}" --clients 1 \
  -- \
  "${REPO_ROOT}/UET/src/Test/MRDescReadLibfabricTest" --mode client --local-port 4301 --peer-port 4300 --timeout-ms "${DEFAULT_TIMEOUT_MS}" --clients 1 --client-id 0 \
  || failures=$((failures + 1))

run_single_case \
  "MRRegLibfabricTest-soft" "MRRegLibfabricTest soft PASS" \
  "${REPO_ROOT}/UET/src/Test/MRRegLibfabricTest" \
  || failures=$((failures + 1))

run_single_case \
  "MRRegLibfabricTest-rdma" "MRRegLibfabricTest rdma PASS" \
  env UET_BACKEND=rdma "${REPO_ROOT}/UET/src/Test/MRRegLibfabricTest" \
  || failures=$((failures + 1))

if (( failures > 0 )); then
  log "[FAIL] control-plane smoke completed with ${failures} failing case(s)"
  exit 1
fi

log "[PASS] control-plane libfabric smoke succeeded"
exit 0

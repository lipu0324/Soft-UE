#!/usr/bin/env bash
set -euo pipefail

DATE_TAG="${1:-$(date +%F)}"
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"

if [[ -f "${HOME}/.uet_ofi_env.sh" ]]; then
  # shellcheck disable=SC1090
  source "${HOME}/.uet_ofi_env.sh"
fi

if [[ -f "${HOME}/nccl-tests/Makefile" ]]; then
  NTEST_DIR="${HOME}/nccl-tests"
elif [[ -f "${HOME}/nccl-tests/nccl-tests/Makefile" ]]; then
  NTEST_DIR="${HOME}/nccl-tests/nccl-tests"
else
  echo "[FAIL] cannot find nccl-tests Makefile under ~/nccl-tests" >&2
  exit 1
fi

BIN="${NTEST_DIR}/build/all_reduce_perf"
if [[ ! -x "${BIN}" ]]; then
  echo "[FAIL] missing binary: ${BIN}" >&2
  exit 1
fi

LOG_DIR="${NTEST_DIR}/logs/phase1_singlegpu_${DATE_TAG}"
mkdir -p "${LOG_DIR}"

export FI_PROVIDER='uet;ofi_rxd'
export NCCL_DEBUG="${NCCL_DEBUG:-INFO}"
export NCCL_DEBUG_SUBSYS="${NCCL_DEBUG_SUBSYS:-INIT,NET}"

run_and_log() {
  local name="$1"
  shift
  local log="${LOG_DIR}/${name}.log"
  echo "[RUN] ${name}"
  "$@" 2>&1 | tee "${log}"
}

run_and_log baseline_g1_8M \
  env -u NCCL_NET_PLUGIN -u OFI_NCCL_PROTOCOL -u FI_PROVIDER -u FI_PROVIDER_PATH \
  NCCL_DEBUG="${NCCL_DEBUG}" NCCL_DEBUG_SUBSYS="${NCCL_DEBUG_SUBSYS}" \
  "${BIN}" -b 8 -e 8M -f 2 -g 1 -n 50

run_and_log ofi_uet_rxd_g1_8M \
  "${BIN}" -b 8 -e 8M -f 2 -g 1 -n 50

run_and_log ofi_uet_rxd_g1_64M_long \
  "${BIN}" -b 8 -e 64M -f 2 -g 1 -n 200

check_log_common() {
  local file="$1"
  rg -q "Collective test concluded: all_reduce_perf" "${file}"
  rg -q "Out of bounds values : 0 OK" "${file}"
  ! rg -q "Segmentation fault|Test CUDA failure|core dumped" "${file}"
}

check_log_ofi() {
  local file="$1"
  rg -q "Selected provider is uet;ofi_rxd" "${file}"
  rg -q "Successfully loaded external network plugin" "${file}"
}

BASELINE_LOG="${LOG_DIR}/baseline_g1_8M.log"
OFI_SHORT_LOG="${LOG_DIR}/ofi_uet_rxd_g1_8M.log"
OFI_LONG_LOG="${LOG_DIR}/ofi_uet_rxd_g1_64M_long.log"

check_log_common "${BASELINE_LOG}"
check_log_common "${OFI_SHORT_LOG}"
check_log_common "${OFI_LONG_LOG}"
check_log_ofi "${OFI_SHORT_LOG}"
check_log_ofi "${OFI_LONG_LOG}"

GATE_SCRIPT="${SCRIPT_DIR}/generate_nccl_regression_gate_report.sh"
if [[ ! -x "${GATE_SCRIPT}" ]]; then
  echo "[FAIL] missing executable gate script: ${GATE_SCRIPT}" >&2
  exit 1
fi

"${GATE_SCRIPT}" "${DATE_TAG}" "${LOG_DIR}"

echo "[PASS] single-GPU NCCL/OFI smoke regression succeeded"
echo "[INFO] logs: ${LOG_DIR}"

#!/usr/bin/env bash
set -euo pipefail

DATE_TAG="${1:-$(date +%F)}"
LOG_DIR="${2:-}"

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd -- "${SCRIPT_DIR}/.." && pwd)"

if [[ -z "${LOG_DIR}" ]]; then
  if [[ -f "${HOME}/nccl-tests/Makefile" ]]; then
    NTEST_DIR="${HOME}/nccl-tests"
  elif [[ -f "${HOME}/nccl-tests/nccl-tests/Makefile" ]]; then
    NTEST_DIR="${HOME}/nccl-tests/nccl-tests"
  else
    echo "[FAIL] cannot find nccl-tests Makefile under ~/nccl-tests" >&2
    exit 1
  fi
  LOG_DIR="${NTEST_DIR}/logs/phase1_singlegpu_${DATE_TAG}"
fi

BASELINE_LOG="${LOG_DIR}/baseline_g1_8M.log"
OFI_SHORT_LOG="${LOG_DIR}/ofi_uet_rxd_g1_8M.log"
OFI_LONG_LOG="${LOG_DIR}/ofi_uet_rxd_g1_64M_long.log"

for required in "${BASELINE_LOG}" "${OFI_SHORT_LOG}" "${OFI_LONG_LOG}"; do
  if [[ ! -f "${required}" ]]; then
    echo "[FAIL] missing log file: ${required}" >&2
    exit 1
  fi
done

count_warn_total() {
  local file="$1"
  awk '/NCCL WARN/{c++} END{print c+0}' "${file}"
}

count_warn_disallowed() {
  local file="$1"
  awk '
    /NCCL WARN/ &&
    $0 !~ /pciPath: Could not find real path/ &&
    $0 !~ /Error opening file: \/sys\/devices\/virtual\/dmi\/id\/product_name/ {c++}
    END{print c+0}
  ' "${file}"
}

yesno() {
  local value="$1"
  if [[ "${value}" -eq 1 ]]; then
    echo "yes"
  else
    echo "no"
  fi
}

bool_has() {
  local pattern="$1"
  local file="$2"
  if rg -q "${pattern}" "${file}"; then
    echo 1
  else
    echo 0
  fi
}

eval_case() {
  local file="$1"
  local need_provider="$2"

  local provider_hit=1
  local collective_done
  local oob_ok
  local crash_free
  local warn_total
  local warn_disallowed
  local allowed_warn_only=0
  local verdict=0

  collective_done="$(bool_has "Collective test concluded: all_reduce_perf" "${file}")"
  oob_ok="$(bool_has "Out of bounds values : 0 OK" "${file}")"

  if rg -q "Segmentation fault|Test CUDA failure|core dumped" "${file}"; then
    crash_free=0
  else
    crash_free=1
  fi

  warn_total="$(count_warn_total "${file}")"
  warn_disallowed="$(count_warn_disallowed "${file}")"
  if [[ "${warn_disallowed}" -eq 0 ]]; then
    allowed_warn_only=1
  fi

  if [[ "${need_provider}" -eq 1 ]]; then
    provider_hit="$(bool_has "Selected provider is uet;ofi_rxd" "${file}")"
    if [[ "$(bool_has "Successfully loaded external network plugin" "${file}")" -eq 0 ]]; then
      provider_hit=0
    fi
  fi

  if [[ "${need_provider}" -eq 1 ]]; then
    if [[ "${provider_hit}" -eq 1 && "${collective_done}" -eq 1 && "${oob_ok}" -eq 1 && "${crash_free}" -eq 1 && "${allowed_warn_only}" -eq 1 ]]; then
      verdict=1
    fi
  else
    if [[ "${collective_done}" -eq 1 && "${oob_ok}" -eq 1 && "${crash_free}" -eq 1 && "${allowed_warn_only}" -eq 1 ]]; then
      verdict=1
    fi
  fi

  echo "${provider_hit} ${collective_done} ${oob_ok} ${crash_free} ${allowed_warn_only} ${warn_total} ${warn_disallowed} ${verdict}"
}

read -r b_provider b_collective b_oob b_crash b_warnonly b_warn b_warn_bad b_verdict <<< "$(eval_case "${BASELINE_LOG}" 0)"
read -r s_provider s_collective s_oob s_crash s_warnonly s_warn s_warn_bad s_verdict <<< "$(eval_case "${OFI_SHORT_LOG}" 1)"
read -r l_provider l_collective l_oob l_crash l_warnonly l_warn l_warn_bad l_verdict <<< "$(eval_case "${OFI_LONG_LOG}" 1)"

overall=0
if [[ "${b_verdict}" -eq 1 && "${s_verdict}" -eq 1 && "${l_verdict}" -eq 1 ]]; then
  overall=1
fi

REPORT_PATH="${LOG_DIR}/regression_gate_${DATE_TAG}.md"
mkdir -p "${LOG_DIR}"

generated_at="$(date '+%F %T %z')"

cat > "${REPORT_PATH}" <<EOF
# NCCL Single-GPU Regression Gate Report (${DATE_TAG})

- Generated at: ${generated_at}
- Policy: function-first (allow known WSL warnings)
- Scope: single-machine single-rank smoke regression (not network bandwidth validation)

## Gate Criteria
- Required hits:
  - \`Collective test concluded: all_reduce_perf\`
  - \`Out of bounds values : 0 OK\`
  - no \`Segmentation fault|core dumped|Test CUDA failure\`
- OFI scenarios additionally require:
  - \`Selected provider is uet;ofi_rxd\`
  - \`Successfully loaded external network plugin\`
- Allowed warning patterns:
  - \`NCCL WARN NET/OFI pciPath: Could not find real path ...\`
  - \`NCCL WARN NET/OFI Error opening file: /sys/devices/virtual/dmi/id/product_name\`

## Result Matrix
| scenario | provider_hit | collective_done | oob_ok | crash_free | allowed_warn_only | warn_count | disallowed_warn_count | verdict |
|---|---|---|---|---|---|---|---|---|
| baseline_g1_8M | n/a | $(yesno "${b_collective}") | $(yesno "${b_oob}") | $(yesno "${b_crash}") | $(yesno "${b_warnonly}") | ${b_warn} | ${b_warn_bad} | $(yesno "${b_verdict}") |
| ofi_uet_rxd_g1_8M | $(yesno "${s_provider}") | $(yesno "${s_collective}") | $(yesno "${s_oob}") | $(yesno "${s_crash}") | $(yesno "${s_warnonly}") | ${s_warn} | ${s_warn_bad} | $(yesno "${s_verdict}") |
| ofi_uet_rxd_g1_64M_long | $(yesno "${l_provider}") | $(yesno "${l_collective}") | $(yesno "${l_oob}") | $(yesno "${l_crash}") | $(yesno "${l_warnonly}") | ${l_warn} | ${l_warn_bad} | $(yesno "${l_verdict}") |

## Overall
- regression_gate_pass: $(yesno "${overall}")
- note: single-rank run may report \`busbw=0\`; this is expected and not a failure criterion.
EOF

REPO_LOG_DIR="${REPO_ROOT}/logs"
mkdir -p "${REPO_LOG_DIR}"
REPO_REPORT_PATH="${REPO_LOG_DIR}/regression_gate_${DATE_TAG}.md"
cp "${REPORT_PATH}" "${REPO_REPORT_PATH}"

echo "[INFO] gate report: ${REPORT_PATH}"
echo "[INFO] repo copy: ${REPO_REPORT_PATH}"
if [[ "${overall}" -eq 1 ]]; then
  echo "[PASS] regression gate passed"
else
  echo "[FAIL] regression gate failed"
  exit 1
fi

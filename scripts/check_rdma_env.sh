#!/usr/bin/env bash
set -euo pipefail

echo "[RDMA-ENV] date: $(date '+%Y-%m-%d %H:%M:%S %z')"
echo "[RDMA-ENV] host: $(hostname)"
echo "[RDMA-ENV] uname: $(uname -a)"

if grep -qi microsoft /proc/version 2>/dev/null; then
  echo "[RDMA-ENV] platform: WSL-like environment detected"
else
  echo "[RDMA-ENV] platform: native Linux"
fi

echo
if [[ -f /usr/include/infiniband/verbs.h ]]; then
  echo "[RDMA-ENV] verbs header: present"
else
  echo "[RDMA-ENV] verbs header: missing"
fi

# Consume ldconfig output before grep: grep -q can otherwise cause SIGPIPE
# in ldconfig, making pipefail incorrectly report an installed library missing.
rdma_ldconfig_cache="$(ldconfig -p 2>/dev/null || true)"
if grep -q libibverbs <<< "$rdma_ldconfig_cache"; then
  echo "[RDMA-ENV] libibverbs: present"
else
  echo "[RDMA-ENV] libibverbs: missing"
fi

echo "[RDMA-ENV] locked memory limit (KiB): $(ulimit -l)"
if command -v rdma >/dev/null 2>&1; then
  rdma link show || true
fi

if pkg-config --exists libfabric 2>/dev/null; then
  echo "[RDMA-ENV] libfabric: $(pkg-config --modversion libfabric) (pkg-config)"
else
  echo "[RDMA-ENV] libfabric: not on the current pkg-config path"
  for rdma_prefix in "${UET_LOCAL_LIBFABRIC_PREFIX:-}" "$HOME/opt/libfabric-2.3.1" "$HOME/opt/libfabric" /opt/libfabric; do
    if [[ -n "$rdma_prefix" && -f "$rdma_prefix/lib/pkgconfig/libfabric.pc" ]]; then
      echo "[RDMA-ENV] libfabric.pc found: $rdma_prefix/lib/pkgconfig/libfabric.pc"
    fi
  done
fi

echo
if command -v ibv_devices >/dev/null 2>&1; then
  echo "[RDMA-ENV] ibv_devices:"
  ibv_devices || true
else
  echo "[RDMA-ENV] ibv_devices: command not found"
fi

echo
if command -v ibv_devinfo >/dev/null 2>&1; then
  echo "[RDMA-ENV] ibv_devinfo:"
  ibv_devinfo || true
else
  echo "[RDMA-ENV] ibv_devinfo: command not found"
fi

echo
if [[ -d /sys/class/infiniband ]]; then
  echo "[RDMA-ENV] /sys/class/infiniband:"
  ls -1 /sys/class/infiniband || true
else
  echo "[RDMA-ENV] /sys/class/infiniband: missing"
fi

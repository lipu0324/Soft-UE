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

if ldconfig -p 2>/dev/null | grep -q libibverbs; then
  echo "[RDMA-ENV] libibverbs: present"
else
  echo "[RDMA-ENV] libibverbs: missing"
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


#!/usr/bin/env bash
set -euo pipefail

if [[ "${EUID}" -eq 0 ]]; then
  SUDO=""
else
  SUDO="sudo"
fi

echo "[1/5] backup apt source files"
$SUDO cp /etc/apt/sources.list /etc/apt/sources.list.bak.$(date +%Y%m%d-%H%M%S)

for f in \
  /etc/apt/sources.list.d/graphics-drivers-ubuntu-ppa-jammy.list \
  /etc/apt/sources.list.d/nodesource.list \
  /etc/apt/sources.list.d/pgdg.list \
  /etc/apt/sources.list.d/cuda-ubuntu2204-x86_64.list
do
  if [[ -f "$f" ]]; then
    $SUDO cp "$f" "$f.bak.$(date +%Y%m%d-%H%M%S)"
  fi
done

echo "[2/5] rewrite /etc/apt/sources.list to Ubuntu 22.04 jammy only"
$SUDO tee /etc/apt/sources.list >/dev/null <<'EOF'
deb https://mirrors.aliyun.com/ubuntu/ jammy main restricted universe multiverse
deb-src https://mirrors.aliyun.com/ubuntu/ jammy main restricted universe multiverse

deb https://mirrors.aliyun.com/ubuntu/ jammy-security main restricted universe multiverse
deb-src https://mirrors.aliyun.com/ubuntu/ jammy-security main restricted universe multiverse

deb https://mirrors.aliyun.com/ubuntu/ jammy-updates main restricted universe multiverse
deb-src https://mirrors.aliyun.com/ubuntu/ jammy-updates main restricted universe multiverse

deb https://mirrors.aliyun.com/ubuntu/ jammy-backports main restricted universe multiverse
deb-src https://mirrors.aliyun.com/ubuntu/ jammy-backports main restricted universe multiverse
EOF

echo "[3/5] set temporary DNS on eno4"
$SUDO resolvectl dns eno4 1.1.1.1 8.8.8.8
$SUDO resolvectl flush-caches

echo "[4/5] DNS status"
resolvectl status | sed -n '1,80p'

echo "[5/5] test apt indexes"
$SUDO apt update

echo
echo "[done] apt sources and DNS refresh completed"

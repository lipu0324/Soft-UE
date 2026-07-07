#!/usr/bin/env bash

UET_LOCAL_RDMA_ROOT="${UET_LOCAL_RDMA_ROOT:-$HOME/opt/uet-sysroot}"
UET_LOCAL_LIBFABRIC_PREFIX="${UET_LOCAL_LIBFABRIC_PREFIX:-$HOME/opt/libfabric}"

export UET_LOCAL_RDMA_ROOT
export UET_LOCAL_LIBFABRIC_PREFIX

export CC="${CC:-/usr/bin/gcc}"
export CXX="${CXX:-/usr/bin/g++}"
export AR="${AR:-/usr/bin/ar}"
export NM="${NM:-/usr/bin/nm}"
export RANLIB="${RANLIB:-/usr/bin/ranlib}"
export STRIP="${STRIP:-/usr/bin/strip}"

export PATH="$UET_LOCAL_LIBFABRIC_PREFIX/bin:$PATH"
export LD_LIBRARY_PATH="$UET_LOCAL_LIBFABRIC_PREFIX/lib:$UET_LOCAL_RDMA_ROOT/usr/lib/x86_64-linux-gnu:${LD_LIBRARY_PATH:-}"
export LIBRARY_PATH="$UET_LOCAL_LIBFABRIC_PREFIX/lib:$UET_LOCAL_RDMA_ROOT/usr/lib/x86_64-linux-gnu:${LIBRARY_PATH:-}"
export CPATH="$UET_LOCAL_LIBFABRIC_PREFIX/include:$UET_LOCAL_RDMA_ROOT/usr/include:$UET_LOCAL_RDMA_ROOT/usr/include/libnl3:${CPATH:-}"

unset PKG_CONFIG_SYSROOT_DIR
unset PKG_CONFIG_LIBDIR
export PKG_CONFIG_PATH="$UET_LOCAL_LIBFABRIC_PREFIX/lib/pkgconfig:$UET_LOCAL_RDMA_ROOT/usr/lib/x86_64-linux-gnu/pkgconfig:${PKG_CONFIG_PATH:-}"

export LIBFABRIC_PREFIX="$UET_LOCAL_LIBFABRIC_PREFIX"
export LIBFABRIC_INCLUDE="$UET_LOCAL_LIBFABRIC_PREFIX/include"
export LIBFABRIC_LIB="$UET_LOCAL_LIBFABRIC_PREFIX/lib"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
export FI_PROVIDER_PATH="${FI_PROVIDER_PATH:-$REPO_ROOT/uet_provider}"

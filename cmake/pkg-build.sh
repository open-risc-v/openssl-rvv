#!/usr/bin/env bash
# openssl：perl Configure + make，静态库（no-shared）装到 <OUT>/prefix。
# 目标三元组按宿主架构选：Apple Silicon 用 darwin64-arm64-cc，Intel 用 darwin64-x86_64-cc。
set -euo pipefail
SRC=$1
OUT=$2
rm -rf "${OUT}"
mkdir -p "${OUT}/prefix"
case "$(uname -m)" in
  arm64|aarch64) tgt=darwin64-arm64-cc ;;
  x86_64)        tgt=darwin64-x86_64-cc ;;
  *)             tgt=linux-x86_64 ;;
esac
cd "${SRC}"
perl ./Configure --prefix="${OUT}/prefix" --libdir=lib no-shared no-tests \
  no-legacy no-docs --openssldir="${OUT}/prefix/ssl" "${tgt}" >/dev/null
make -j"$(sysctl -n hw.ncpu 2>/dev/null || echo 4)" build_sw >/dev/null
make install_sw >/dev/null
echo "== 上游 openssl 构建完成：${OUT}/prefix（${tgt}）"

#!/usr/bin/env bash
# openssl：perl Configure + make，静态库（no-shared）装到 <OUT>/prefix。
# 必须 out-of-source 构建：在 <OUT>/bld 里 configure，源码树保持纯净——
# 源码树内 configure 会往 baseline/ 写 Makefile 与 .d，baseline 就不再是原始参照。
set -euo pipefail
SRC=$1
OUT=$2
rm -rf "${OUT}"
mkdir -p "${OUT}/bld"
# 目标名必须同时看 OS 与架构：只按架构选会把 Linux 容器里的 aarch64 选成 darwin 目标，
# 于是编译命令里出现 -arch（GCC 不认）。
case "$(uname -s)" in
  Darwin)
    case "$(uname -m)" in
      arm64|aarch64) tgt=darwin64-arm64-cc ;;
      x86_64)        tgt=darwin64-x86_64-cc ;;
      *)             tgt=darwin64-x86_64-cc ;;
    esac ;;
  Linux)
    case "$(uname -m)" in
      aarch64|arm64) tgt=linux-aarch64 ;;
      riscv64)       tgt=linux64-riscv64 ;;
      *)             tgt=linux-x86_64 ;;
    esac ;;
  *) tgt=linux-x86_64 ;;
esac
cd "${OUT}/bld"
perl "${SRC}/Configure" --prefix="${OUT}/prefix" --libdir=lib no-shared no-tests \
  no-legacy no-docs --openssldir="${OUT}/prefix/ssl" "${tgt}" >/dev/null
make -j"$(getconf _NPROCESSORS_ONLN 2>/dev/null || echo 4)" build_sw >/dev/null
make install_sw >/dev/null
echo "== 上游 openssl 构建完成：${OUT}/prefix（${tgt}，out-of-source）"

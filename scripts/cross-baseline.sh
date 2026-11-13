#!/usr/bin/env bash
# 交叉编译基线版本：openssl 用 perl Configure 的 linux64-riscv64 目标，
# 静态库装到 build/riscv64-b/prefix，探针用 qemu-user 跑，与 native 基线比对。
#
#   ./scripts/cross-baseline.sh
#   OPENSSL_TGT=linux64-riscv64-noasm ./scripts/cross-baseline.sh   # 汇编不过时退这一步
set -euo pipefail
cd "$(dirname "$0")/.."

IMAGE=${IMAGE:-rvv-cross:1}
MARCH=${MARCH:-rv64gc}
TGT=${OPENSSL_TGT:-linux64-riscv64}
OUT=build/riscv64-b

docker run --rm -v "$PWD":/work -w /work "${IMAGE}" bash -lc "
set -e
rm -rf ${OUT}
mkdir -p ${OUT}/bld
cd ${OUT}/bld
CC='riscv64-linux-gnu-gcc' AR='riscv64-linux-gnu-ar' RANLIB='riscv64-linux-gnu-ranlib' \
perl /work/baseline/Configure --prefix=/work/${OUT}/prefix --libdir=lib \
  no-shared no-tests no-legacy no-docs --openssldir=/work/${OUT}/prefix/ssl \
  -march=${MARCH} ${TGT} > /tmp/cfg.log 2>&1 || { tail -20 /tmp/cfg.log; exit 1; }
make -j\$(nproc) build_sw > /tmp/bld.log 2>&1 || { tail -20 /tmp/bld.log; exit 1; }
make install_sw > /dev/null

cmake -S /work -B /work/${OUT}/harness -DCMAKE_BUILD_TYPE=Release \
  -DCMAKE_TOOLCHAIN_FILE=/work/cmake/toolchain-riscv64-linux.cmake \
  -DCMAKE_C_FLAGS='-march=${MARCH}' -DPKG_PREFIX=/work/${OUT}/prefix \
  > /tmp/h.log 2>&1 || { tail -20 /tmp/h.log; exit 1; }
cmake --build /work/${OUT}/harness -j > /tmp/hb.log 2>&1 || { tail -20 /tmp/hb.log; exit 1; }

cd /work
mkdir -p ${OUT}/out
qemu-riscv64 -L /usr/riscv64-linux-gnu ${OUT}/harness/ossl_harness ${OUT}/out/cipher.bin > ${OUT}/out/hash.txt
echo \"--- riscv64（${MARCH}, ${TGT}）---\"; cat ${OUT}/out/hash.txt
echo \"--- native 基线 ---\"; cat build/ab-data/out/01_openssl_aes/a/hash.txt
"

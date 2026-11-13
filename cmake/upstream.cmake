# 上游接入：openssl 用 perl Configure（非 CMake），先编进 <build>/pkg/prefix，
# 探针链接 libcrypto 静态库。A/B 各自独立前缀 → 各自独立的汇编/SIMD 实现。

set(PKG_ROOT "${CMAKE_BINARY_DIR}/pkg")
set(PKG_PREFIX "${PKG_ROOT}/prefix")

add_custom_target(pkg ALL
  COMMAND "${CMAKE_CURRENT_SOURCE_DIR}/cmake/pkg-build.sh" "${SRC_DIR}" "${PKG_ROOT}"
  COMMENT "构建上游 openssl（${SRC_DIR}，静态）"
  VERBATIM)

add_executable(ossl_harness test/pkg_ossl.c)
add_dependencies(ossl_harness pkg)
target_include_directories(ossl_harness PRIVATE "${PKG_PREFIX}/include")
target_link_directories(ossl_harness PRIVATE "${PKG_PREFIX}/lib")
target_link_libraries(ossl_harness PRIVATE crypto pthread)
target_compile_options(ossl_harness PRIVATE ${RVV_FLAGS})

add_test(NAME ossl_harness COMMAND ossl_harness)

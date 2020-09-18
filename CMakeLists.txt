cmake_minimum_required(VERSION 3.5)
project(ntrusign)

add_compile_options(-Wall -g)
set(CMAKE_CXX_STANDARD 14)

add_subdirectory(NTRUSignKeyChain)

SET(PREFIX /usr/local)
set(CURRENT_SOURCES src/bench.c
        src/bsparseconv.c
        src/crypto_hash_sha512.c
        src/crypto_stream.c
        src/fastrandombytes.c
        src/formatc.c
        src/hash.c
        src/key.c
        src/ntt.c
        src/poly.c
        src/randombytes.c
        src/sign.c
        src/verify.c)

set(CURRENT_INCLUDE src/bsparseconv.h
        src/constants.h
        src/crypto_hash_sha512.h
        src/crypto_stream_salsa20.h
        src/fastrandombytes.h
        src/formatc.h
        src/hash.h
        src/ntt.h
        src/pass.h
        src/pass_types.h
        src/poly.h
        src/randombytes.h)

add_executable(bench ${CURRENT_SOURCES})
target_link_libraries(bench fftw3 m)

ADD_LIBRARY(ntrusign SHARED ${CURRENT_SOURCES} ${CURRENT_INCLUDE})
ADD_LIBRARY(ntrusign_static STATIC ${CURRENT_SOURCES} ${CURRENT_INCLUDE})
SET_TARGET_PROPERTIES(ntrusign_static PROPERTIES OUTPUT_NAME "ntrusign")

INSTALL(FILES ${CURRENT_INCLUDE} DESTINATION ${PREFIX}/include/ntrusign)

INSTALL(TARGETS ntrusign ntrusign_static
        LIBRARY DESTINATION ${PREFIX}/lib
        ARCHIVE DESTINATION ${PREFIX}/lib)

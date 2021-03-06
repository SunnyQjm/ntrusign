cmake_minimum_required(VERSION 3.5)

add_compile_options(-Wall -g)
set(CMAKE_CXX_STANDARD 14)

set(CURRENT_SOURCES
        ../src/bsparseconv.c
        ../src/crypto_hash_sha512.c
        ../src/crypto_stream.c
        ../src/fastrandombytes.c
        ../src/formatc.c
        ../src/hash.c
        ../src/key.c
        ../src/ntt.c
        ../src/poly.c
        ../src/randombytes.c
        ../src/sign.c
        ../src/verify.c)

add_executable(test_ntru src/utils/NTRUSignUtil.cpp src/utils/NTRUSignUtil.h src/main.cpp src/PrivateKey.cpp
        src/PrivateKey.h src/Signature.cpp src/Signature.h src/PublicKey.cpp src/PublicKey.h src/Buffer.h
        #src/NTRUKeyChain.cpp src/NTRUKeyChain.h src/tpm/Tpm.cpp src/tpm/Tpm.h src/tpm/KeyHandle.cpp src/tpm/KeyHandle.h src/tpm/KeyHandleMem.cpp src/tpm/KeyHandleMem.h src/tpm/BackEnd.cpp src/tpm/BackEnd.h src/common.h src/tpm/BackEndFile.cpp src/tpm/BackEndFile.h
        )
target_link_libraries(test_ntru ntrusign fftw3 m boost_system ndn-cxx)
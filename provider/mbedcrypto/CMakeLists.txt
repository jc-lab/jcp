cmake_minimum_required(VERSION 3.4)
project(jcp_provider_mbedcrypto)

set(CMAKE_MODULE_PATH ${CMAKE_SOURCE_DIR}/cmake)

set(CMAKE_CXX_STANDARD 11)

add_library(jcp_provider_mbedcrypto src/mbedcrypto_cipher_asym.cpp src/mbedcrypto_cipher_sym.cpp src/mbedcrypto_ka_ecdh.cpp src/mbedcrypto_md.cpp src/mbedcrypto_provider.cpp src/mbedcrypto_securerandom.cpp src/mbedcrypto_sign.cpp src/mbedcrypto_key_utils.cpp src/mbedcrypto_key_factory.hpp src/mbedcrypto_key_factory.cpp src/mbedcrypto_key_pair_generator.hpp src/mbedcrypto_key_pair_generator.cpp)

find_package(MbedCrypto REQUIRED)
if(MBEDCRYPTO_FOUND  AND  MBEDCRYPTO_INCLUDE_DIR  AND  MBEDCRYPTO_LIBRARIES)
    add_definitions(-DHAS_MBEDCRYPTO)
    include_directories(${MBEDCRYPTO_INCLUDE_DIR})
    set(EXTRA_LIBS ${EXTRA_LIBS} ${MBEDCRYPTO_LIBRARIES})
    set(_MBEDCRYPTO_VERSION_ ${MBEDCRYPTO_VERSION})
    message("-- mbedTLS ${MBEDCRYPTO_VERSION} found!")
else()
    message("-- mbedTLS not found!")
    return()
endif()

include_directories(../../include)

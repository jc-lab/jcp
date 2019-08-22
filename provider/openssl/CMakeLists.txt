cmake_minimum_required(VERSION 3.4)
project(jcp_provider_openssl)

set(CMAKE_CXX_STANDARD 11)

add_library(${PROJECT_NAME} src/openssl_cipher_asym.cpp src/openssl_cipher_asym.hpp src/openssl_cipher_sym.cpp src/openssl_cipher_sym.hpp src/openssl_ka_ecdh.cpp src/openssl_ka_ecdh.hpp src/openssl_md.cpp src/openssl_md.hpp src/openssl_provider.cpp ../../include/jcp/openssl_provider.hpp src/openssl_securerandom.cpp src/openssl_securerandom.hpp src/openssl_sign.cpp src/openssl_sign.hpp src/openssl_key_utils.hpp src/mbedcrypto_key_utils.cpp)

find_package(OpenSSL REQUIRED)
if(OPENSSL_FOUND)
    target_link_libraries(${PROJECT_NAME} OpenSSL::Crypto)
    add_definitions(-DHAS_OPENSSL)
    include_directories(${OPENSSL_INCLUDE_DIR})
    set(EXTRA_LIBS ${EXTRA_LIBS} ${OPENSSL_CRYPTO_LIBRARY})
    message("-- OpenSSL ${OPENSSL_VERSION} found!")
else()
    message("-- OpenSSL not found!")
    return()
endif()

include_directories(../../include)

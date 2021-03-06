cmake_minimum_required(VERSION 3.4)
project(jcp_example)

set(CMAKE_MODULE_PATH ${CMAKE_SOURCE_DIR}/cmake)

set(CMAKE_CXX_STANDARD 11)

add_executable(jcp_example example.cpp)

target_link_libraries(jcp_example jcp)
include_directories(${CMAKE_SOURCE_DIR}/include)

find_package(MbedCrypto REQUIRED)
message("MBEDCRYPTO_LIBRARIES : ${MBEDCRYPTO_LIBRARIES}")
if(MBEDCRYPTO_FOUND  AND  MBEDCRYPTO_INCLUDE_DIR  AND  MBEDCRYPTO_LIBRARIES)
    add_definitions(-DJCP_USE_MBEDCRYPTO=1)
    include_directories(${MBEDCRYPTO_INCLUDE_DIR})
    set(EXTRA_LIBS ${EXTRA_LIBS} ${MBEDCRYPTO_LIBRARIES})
    set(_MBEDCRYPTO_VERSION_ ${MBEDCRYPTO_VERSION})
    message("-- mbedTLS ${MBEDCRYPTO_VERSION} found!")

    target_link_libraries(jcp_example jcp_provider_mbedcrypto)
    include_directories(${CMAKE_SOURCE_DIR}/provider/mbedcrypto/src/)
else()
    message("-- mbedTLS not found!")
    return()
endif()

find_package(OpenSSL REQUIRED)
if(OPENSSL_FOUND)
    add_definitions(-DJCP_USE_OPENSSL=1)
    target_link_libraries(${PROJECT_NAME} OpenSSL::Crypto)
    add_definitions(-DHAS_OPENSSL)
    include_directories(${OPENSSL_INCLUDE_DIR})
    set(EXTRA_LIBS ${EXTRA_LIBS} ${OPENSSL_CRYPTO_LIBRARY})
    message("-- OpenSSL ${OPENSSL_VERSION} found!")

    target_link_libraries(jcp_example jcp_provider_openssl)
else()
    message("-- OpenSSL not found!")
    return()
endif()

target_link_libraries(jcp_example ${EXTRA_LIBS})

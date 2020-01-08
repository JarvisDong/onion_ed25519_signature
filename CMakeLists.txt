cmake_minimum_required(VERSION 3.13)
project(ed25519_sign_verify C)

set(CMAKE_C_STANDARD 99)

set(HEADERS
        header/curve25519-donna-64bit.h
        header/curve25519-donna-helpers.h
        header/ed25519-donna.h
        header/ed25519-donna-64bit-tables.h
        header/ed25519-donna-64bit-x86.h
        header/ed25519-donna-basepoint-table.h
        header/ed25519-donna-impl-base.h
        header/ed25519-donna-portable.h
        header/ed25519-donna-portable-identify.h
        header/ed25519-hash.h
        header/modm-donna-64bit.h
        header/orconfig.h
        )

set (SOURCES
        src/verify.c
        header/sign.h src/sign.c)

set(OPENSSL_USE_STATIC_LIBS TRUE)
find_package(OpenSSL REQUIRED)

add_executable(ed25519_sign_verify main.c ${HEADERS} ${SOURCES})
target_link_libraries(${PROJECT_NAME} OpenSSL::Crypto)

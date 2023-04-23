cmake_minimum_required (VERSION 3.5)
project (wstunnel)

if(UNIX AND NOT APPLE)
    set(OPENSSL_ROOT_DIR "/usr/local/ssl")
elseif(APPLE)
    set(OPENSSL_ROOT_DIR "/usr/local/opt/openssl")
endif()

find_package (OpenSSL REQUIRED)

set (WSTUNNEL_SOURCES
    wstunnel.cpp
)

# set (CLIENT_SOURCES
#     client.cpp
# )

add_executable (wstunnel ${WSTUNNEL_SOURCES})
target_link_libraries (wstunnel OpenSSL::SSL OpenSSL::Crypto)

# add_executable (client ${CLIENT_SOURCES})
# target_link_libraries (client OpenSSL::SSL OpenSSL::Crypto)

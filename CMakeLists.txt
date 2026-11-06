cmake_minimum_required(VERSION 3.16)
project(secure_inline_channel LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

find_package(OpenSSL REQUIRED)
find_package(PkgConfig REQUIRED)
pkg_check_modules(NFQUEUE REQUIRED IMPORTED_TARGET libnetfilter_queue)

add_executable(secure_inline
    src/main.cpp
)

target_link_libraries(secure_inline PRIVATE OpenSSL::Crypto PkgConfig::NFQUEUE)
target_compile_options(secure_inline PRIVATE -Wall -Wextra -Wpedantic -Wconversion)

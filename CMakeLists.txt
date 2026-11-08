cmake_minimum_required(VERSION 3.16)
project(ban VERSION 1.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE Release CACHE STRING "Build type" FORCE)
endif()

set(BAN_SOURCES
  src/main.cpp
  src/util.cpp
  src/log.cpp
  src/json.cpp
  src/config.cpp
  src/model.cpp
  src/store.cpp
  src/resolver.cpp
  src/backend.cpp
  src/backend_nft.cpp
  src/backend_iptables.cpp
  src/dns.cpp
  src/commands.cpp
)

add_executable(ban ${BAN_SOURCES})
target_include_directories(ban PRIVATE src)

if(CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
  target_compile_options(ban PRIVATE -Wall -Wextra -Wpedantic -O2)
  # 静态链接 C++ 运行时，便于把二进制拷到其它发行版直接运行
  target_link_options(ban PRIVATE -static-libstdc++ -static-libgcc)
endif()

include(GNUInstallDirs)
install(TARGETS ban RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
install(DIRECTORY systemd/ DESTINATION ${CMAKE_INSTALL_LIBDIR}/systemd/system)
install(FILES README.md DESTINATION ${CMAKE_INSTALL_DOCDIR})

enable_testing()
add_executable(ban_tests tests/unit_main.cpp src/util.cpp src/model.cpp src/json.cpp)
target_include_directories(ban_tests PRIVATE src)
if(CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
  target_compile_options(ban_tests PRIVATE -O1 -g)
endif()
add_test(NAME unit COMMAND ban_tests)

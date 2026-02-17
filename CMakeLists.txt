cmake_minimum_required(VERSION 3.20)
project(EloaneDecryptor VERSION 1.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_AUTOMOC ON)

find_package(Qt6 REQUIRED COMPONENTS Core Gui Widgets)

# ── OpenSSL ──
if(WIN32 AND NOT DEFINED OPENSSL_ROOT_DIR)
  set(OPENSSL_ROOT_DIR "C:/Program Files/OpenSSL-Win64")
endif()
find_package(OpenSSL REQUIRED)

# ── Executable ──
qt_add_executable(EloaneDecryptor WIN32
  main.cpp
)

target_link_libraries(EloaneDecryptor PRIVATE
  Qt6::Core
  Qt6::Gui
  Qt6::Widgets
  OpenSSL::SSL
  OpenSSL::Crypto
)

# ── Install ──
install(TARGETS EloaneDecryptor RUNTIME DESTINATION bin)

cmake_minimum_required(VERSION 3.10)
project(hsm_lite)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED True)

# ==== Fetch Catch2 ====
include(FetchContent)
FetchContent_Declare(
  Catch2
  GIT_REPOSITORY https://github.com/catchorg/Catch2.git
  GIT_TAG v3.6.0 # use latest stable
)
FetchContent_MakeAvailable(Catch2)

# Add the main categories
add_subdirectory(cryptography)
add_subdirectory(keystore)
# Make the crypto library
add_library(symmetric_crypto_lib
    src/SymmetricCryptography.cpp
)

target_include_directories(symmetric_crypto_lib PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/include
)

# Find and link OpenSSL
find_package(OpenSSL REQUIRED)

# Link crypto against core + OpenSSL
target_link_libraries(symmetric_crypto_lib PUBLIC
    core_lib
    OpenSSL::Crypto
)

# Create test executable
add_executable(symmetric_crypto_tests
    test/SymmetricCryptography.test.cpp
)

# Link libraries + Catch2 into tests
target_link_libraries(symmetric_crypto_tests PRIVATE
    symmetric_crypto_lib
    test_support
    Catch2::Catch2WithMain
)

# Enable test discovery
include(CTest)
include(Catch)
catch_discover_tests(symmetric_crypto_tests)
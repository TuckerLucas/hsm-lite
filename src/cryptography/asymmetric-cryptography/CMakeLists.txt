# Make the crypto library
add_library(asymmetric_crypto_lib
    src/AsymmetricCryptography.cpp
)

target_include_directories(asymmetric_crypto_lib PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/include
)

# Find and link OpenSSL
find_package(OpenSSL REQUIRED)

# Link crypto against core + OpenSSL
target_link_libraries(asymmetric_crypto_lib PUBLIC
    core_lib
    OpenSSL::Crypto
)

# Create test executable
add_executable(asymmetric_crypto_tests
    test/AsymmetricCryptography.test.cpp
)

# Link libraries + Catch2 into tests
target_link_libraries(asymmetric_crypto_tests PRIVATE
    asymmetric_crypto_lib
    test_support
    Catch2::Catch2WithMain
)

# Enable test discovery
include(CTest)
include(Catch)
catch_discover_tests(asymmetric_crypto_tests)
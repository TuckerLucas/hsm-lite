# Make the crypto library
add_library(crypto_lib
    src/Cryptography.cpp
)

target_include_directories(crypto_lib PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/include
)

# Create test executable
add_executable(crypto_tests
    test/Cryptography.test.cpp
)

# Link library + Catch2 into tests
target_link_libraries(crypto_tests PRIVATE
    crypto_lib
    keystore_lib
    Catch2::Catch2WithMain
)

# Enable test discovery
include(CTest)
include(Catch)
catch_discover_tests(crypto_tests)

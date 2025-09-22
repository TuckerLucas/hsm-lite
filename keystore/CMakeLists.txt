# keystore/CMakeLists.txt

# Make the keystore library
add_library(keystore_lib
    src/Keystore.cpp
)

target_include_directories(keystore_lib PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/include
)

# Link keystore against core
target_link_libraries(keystore_lib PUBLIC 
    core_lib
    crypto_lib)

# Create test executable
add_executable(keystore_tests
    test/Keystore.test.cpp
)

# Link libraries + Catch2 into tests
target_link_libraries(keystore_tests PRIVATE
    keystore_lib
    Catch2::Catch2WithMain
)

# Enable test discovery
include(CTest)
include(Catch)
catch_discover_tests(keystore_tests)
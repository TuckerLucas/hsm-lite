add_subdirectory(hash)
add_subdirectory(symmetric-cryptography)

add_library(crypto_lib INTERFACE)
target_link_libraries(crypto_lib INTERFACE
    hash_lib
    symmetric_crypto_lib
)
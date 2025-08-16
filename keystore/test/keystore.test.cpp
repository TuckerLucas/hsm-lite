#include <catch2/catch_test_macros.hpp>
#include "keystore.hpp"

TEST_CASE("Simple addition works") {
    REQUIRE(add(2, 2) == 4);
    REQUIRE(add(10, -2) == 8);
}

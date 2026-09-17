#include "test_framework.hpp"

// The suite name is supplied as a plain token by the build system and stringified
// here, so the same file works for every suite.
#define RC_STRINGIFY_IMPL(value) #value
#define RC_STRINGIFY(value) RC_STRINGIFY_IMPL(value)

int main() { return ::rc::test::run_all(RC_STRINGIFY(RC_TEST_SUITE_NAME)); }

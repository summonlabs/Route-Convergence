# Route Convergence test suite.
#
# Every test is registered with CTest plainly: no timeouts, no retries, no
# parallel-resource assumptions that could hide a hang or a race.

set(RC_TEST_SUPPORT ${CMAKE_CURRENT_SOURCE_DIR}/support/test_main.cpp)

function(rc_add_test name)
  add_executable(${name} ${RC_TEST_SUPPORT} ${ARGN})
  target_link_libraries(${name} PRIVATE route_convergence)
  target_include_directories(${name} PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/support)
  target_compile_options(${name} PRIVATE ${RC_WARNING_FLAGS})
  target_compile_definitions(${name} PRIVATE RC_TEST_SUITE_NAME="${name}")
  add_test(NAME ${name} COMMAND ${name})
endfunction()

rc_add_test(rc_test_core test_core.cpp)
rc_add_test(rc_test_governance test_governance.cpp)
rc_add_test(rc_test_persistence test_persistence.cpp)
rc_add_test(rc_test_protocol test_protocol.cpp)
rc_add_test(rc_test_oracle test_oracle.cpp)
rc_add_test(rc_test_property test_property.cpp)
rc_add_test(rc_test_adversarial test_adversarial.cpp)
rc_add_test(rc_test_scale test_scale.cpp)

if(RC_BUILD_APPS)
  add_executable(rc_test_distributed ${RC_TEST_SUPPORT} test_distributed.cpp)
  target_link_libraries(rc_test_distributed PRIVATE route_convergence)
  target_include_directories(rc_test_distributed PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/support)
  target_compile_options(rc_test_distributed PRIVATE ${RC_WARNING_FLAGS})
  target_compile_definitions(rc_test_distributed PRIVATE
    RC_TEST_SUITE_NAME="rc_test_distributed"
    RC_COORDINATOR_EXECUTABLE="$<TARGET_FILE:rc_coordinator>"
    RC_WORKER_EXECUTABLE="$<TARGET_FILE:rc_worker>"
    RC_CLI_EXECUTABLE="$<TARGET_FILE:rc_cli>")
  # The real-process proof needs the application binaries, and
  # $<TARGET_FILE:...> resolves their paths without ordering the build.
  add_dependencies(rc_test_distributed rc_coordinator rc_worker rc_cli)
  add_test(NAME rc_test_distributed COMMAND rc_test_distributed)
endif()

# The independent downstream consumer is deliberately NOT built here: its whole
# purpose is to be configured as a separate project that sees only the installed
# package.  scripts/validate-install.cmd configures and runs it that way.

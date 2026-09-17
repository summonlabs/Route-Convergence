# Route Convergence examples.
#
# Both examples are real executables: they drive the public API end to end and
# exit non-zero at the first failed assertion, so CTest treats them as proofs
# rather than as demonstrations.

add_executable(rc_examples api_examples.cpp)
target_link_libraries(rc_examples PRIVATE route_convergence)
# The in-process example uses the shared deterministic control-plane fixture
# (rc::test::Fixture) exactly like the test suites do.
target_include_directories(rc_examples PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/../tests/support)
target_compile_options(rc_examples PRIVATE ${RC_WARNING_FLAGS})
add_test(NAME rc_examples COMMAND rc_examples)

if(RC_BUILD_APPS)
  # The distributed example starts real coordinator and worker processes, so it
  # must know the exact binaries the current build produced.
  add_executable(rc_examples_distributed distributed_examples.cpp)
  target_link_libraries(rc_examples_distributed PRIVATE route_convergence)
  target_compile_options(rc_examples_distributed PRIVATE ${RC_WARNING_FLAGS})
  target_compile_definitions(rc_examples_distributed PRIVATE
    RC_COORDINATOR_EXECUTABLE="$<TARGET_FILE:rc_coordinator>"
    RC_WORKER_EXECUTABLE="$<TARGET_FILE:rc_worker>")
  # Resolving the executable paths does not order the builds, so the example
  # depends on the applications explicitly and always finds real binaries.
  add_dependencies(rc_examples_distributed rc_coordinator rc_worker)
  add_test(NAME rc_examples_distributed COMMAND rc_examples_distributed)
endif()

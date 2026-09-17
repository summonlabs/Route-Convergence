# Route Convergence benchmarks.
#
# Every benchmark measures COMPLETED operations only: an operation that does not
# succeed fails the run instead of contributing a meaningless timing sample.  The
# benchmark is registered with CTest for the same reason: it proves that every
# measured path really works.

add_executable(rc_benchmark rc_benchmark.cpp)
target_link_libraries(rc_benchmark PRIVATE route_convergence)
target_compile_options(rc_benchmark PRIVATE ${RC_WARNING_FLAGS})
add_test(NAME rc_benchmark COMMAND rc_benchmark)

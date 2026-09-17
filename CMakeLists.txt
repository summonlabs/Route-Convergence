cmake_minimum_required(VERSION 3.25)

project(RouteConvergence
  VERSION 1.0.0
  DESCRIPTION "Deterministic route-transition ordering, dependency-safe state change and convergence-governance runtime"
  LANGUAGES CXX)

include(GNUInstallDirs)
include(CMakePackageConfigHelpers)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
  set(CMAKE_BUILD_TYPE Release CACHE STRING "Build type" FORCE)
endif()

option(RC_BUILD_TESTS "Build the Route Convergence test suite" ON)
option(RC_BUILD_EXAMPLES "Build the Route Convergence examples" ON)
option(RC_BUILD_BENCHMARKS "Build the Route Convergence benchmarks" ON)
option(RC_BUILD_APPS "Build the coordinator, worker and CLI applications" ON)
option(RC_ENABLE_ASAN "Build with MSVC AddressSanitizer" OFF)
option(RC_ENABLE_ANALYZE "Build with MSVC /analyze" OFF)
option(RC_WARNINGS_AS_ERRORS "Treat first-party warnings as errors" ON)

set(RC_WARNING_FLAGS /W4 /permissive- /Zc:__cplusplus /utf-8 /EHsc)
if(RC_WARNINGS_AS_ERRORS)
  list(APPEND RC_WARNING_FLAGS /WX)
endif()
if(RC_ENABLE_ANALYZE)
  list(APPEND RC_WARNING_FLAGS /analyze)
endif()

if(RC_ENABLE_ASAN)
  # MSVC AddressSanitizer requires the dynamic CRT and the sanitizer runtime, and
  # it needs debug information emission to produce usable reports.
  set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>DLL")
  add_compile_options(/fsanitize=address /Zi)
  add_link_options(/fsanitize=address /DEBUG)
  message(STATUS "Route Convergence: AddressSanitizer requested (MSVC /fsanitize=address)")
endif()

add_library(route_convergence STATIC
  src/authority.cpp
  src/backend.cpp
  src/bytes.cpp
  src/client.cpp
  src/digest.cpp
  src/generator.cpp
  src/governor_codec.cpp
  src/governor_control.cpp
  src/governor_core.cpp
  src/governor_mutate.cpp
  src/governor_query.cpp
  src/graph.cpp
  src/identity.cpp
  src/lifecycle.cpp
  src/limits.cpp
  src/outcome.cpp
  src/persistence.cpp
  src/plan.cpp
  src/policy.cpp
  src/process.cpp
  src/protocol.cpp
  src/server.cpp
  src/step.cpp
  src/synthetic.cpp
  src/transport.cpp
  src/upstream.cpp
  src/version.cpp)
add_library(SummonSoftwareLabs::RouteConvergence ALIAS route_convergence)
set_target_properties(route_convergence PROPERTIES
  EXPORT_NAME RouteConvergence
  POSITION_INDEPENDENT_CODE ON)
target_include_directories(route_convergence PUBLIC
  $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
  $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>)
target_compile_options(route_convergence PRIVATE ${RC_WARNING_FLAGS})
target_compile_features(route_convergence PUBLIC cxx_std_20)

if(WIN32)
  target_link_libraries(route_convergence PUBLIC ws2_32)
else()
  message(FATAL_ERROR
    "Route Convergence 1.0.0 targets Windows: the loopback transport, the coordinator "
    "service, the worker client and the real-process proofs are implemented against "
    "Win32/Winsock. The control-plane library itself is portable C++20, but 1.0.0 does "
    "not claim a validated non-Windows build.")
endif()

# --- applications -----------------------------------------------------------
if(RC_BUILD_APPS)
  add_library(rc_app_support STATIC app/support.cpp)
  target_include_directories(rc_app_support PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/app)
  target_link_libraries(rc_app_support PUBLIC route_convergence)
  target_compile_options(rc_app_support PRIVATE ${RC_WARNING_FLAGS})

  add_executable(rc_coordinator app/coordinator_main.cpp)
  target_link_libraries(rc_coordinator PRIVATE rc_app_support)
  target_compile_options(rc_coordinator PRIVATE ${RC_WARNING_FLAGS})

  add_executable(rc_worker app/worker_main.cpp)
  target_link_libraries(rc_worker PRIVATE rc_app_support)
  target_compile_options(rc_worker PRIVATE ${RC_WARNING_FLAGS})

  add_executable(rc_cli app/cli_main.cpp)
  target_link_libraries(rc_cli PRIVATE rc_app_support)
  target_compile_options(rc_cli PRIVATE ${RC_WARNING_FLAGS})
endif()

# --- tests, examples, benchmarks -------------------------------------------
if(RC_BUILD_TESTS)
  enable_testing()
  add_subdirectory(tests)
endif()
if(RC_BUILD_EXAMPLES)
  add_subdirectory(examples)
endif()
if(RC_BUILD_BENCHMARKS)
  add_subdirectory(bench)
endif()

# --- install and export -----------------------------------------------------
install(TARGETS route_convergence
  EXPORT RouteConvergenceTargets
  ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
  LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
  RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
  INCLUDES DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})

if(RC_BUILD_APPS)
  install(TARGETS rc_cli rc_coordinator rc_worker
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
endif()

install(DIRECTORY include/rc
  DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
  FILES_MATCHING PATTERN "*.hpp")

install(EXPORT RouteConvergenceTargets
  FILE RouteConvergenceTargets.cmake
  NAMESPACE SummonSoftwareLabs::
  DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/RouteConvergence)

configure_package_config_file(
  ${CMAKE_CURRENT_SOURCE_DIR}/cmake/RouteConvergenceConfig.cmake.in
  ${CMAKE_CURRENT_BINARY_DIR}/RouteConvergenceConfig.cmake
  INSTALL_DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/RouteConvergence)

write_basic_package_version_file(
  ${CMAKE_CURRENT_BINARY_DIR}/RouteConvergenceConfigVersion.cmake
  VERSION ${PROJECT_VERSION}
  COMPATIBILITY SameMajorVersion)

install(FILES
  ${CMAKE_CURRENT_BINARY_DIR}/RouteConvergenceConfig.cmake
  ${CMAKE_CURRENT_BINARY_DIR}/RouteConvergenceConfigVersion.cmake
  DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/RouteConvergence)

install(FILES LICENSE README.md
  DESTINATION ${CMAKE_INSTALL_DATADIR}/RouteConvergence)

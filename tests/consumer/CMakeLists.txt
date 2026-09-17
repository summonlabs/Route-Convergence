cmake_minimum_required(VERSION 3.25)

# Independent downstream consumer: this project must find Route Convergence
# through find_package(RouteConvergence CONFIG REQUIRED) and must not see the
# Route Convergence source tree on its include path.
project(RouteConvergenceConsumer LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
  set(CMAKE_BUILD_TYPE Release CACHE STRING "Build type" FORCE)
endif()

find_package(RouteConvergence CONFIG REQUIRED)

add_executable(rc_consumer consumer_main.cpp)
target_link_libraries(rc_consumer PRIVATE SummonSoftwareLabs::RouteConvergence)
target_compile_options(rc_consumer PRIVATE /W4 /permissive- /Zc:__cplusplus /utf-8 /EHsc /WX)

cmake_minimum_required(VERSION 3.5)
project(router)

set(CMAKE_CXX_STANDARD 14)
set(EXECUTABLE_OUTPUT_PATH ${PROJECT_SOURCE_DIR})

include_directories(. build)
link_libraries(Ice IceUtil boost_system pthread)

add_executable(router build/pox.cpp arp-cache.cpp routing-table.cpp simple-router.cpp core/utils.cpp core/interface.cpp core/dumper.cpp core/main.cpp)
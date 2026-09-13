cmake_minimum_required(VERSION 3.13)

project(dns-server-starter-cpp)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

file(GLOB_RECURSE SOURCE_FILES CONFIGURE_DEPENDS src/*.cpp src/include/*.hpp)

# Add include directories
include_directories(src src/include)

add_executable(server ${SOURCE_FILES})
target_compile_options(server PRIVATE -Wall -Wextra -pedantic)
target_link_libraries(server PRIVATE pthread)

add_executable(dns_concurrency_test tests/dns_concurrency_test.cpp)
target_include_directories(dns_concurrency_test PRIVATE src/include)
target_compile_options(dns_concurrency_test PRIVATE -Wall -Wextra -pedantic)
target_link_libraries(dns_concurrency_test PRIVATE pthread)

enable_testing()
add_executable(dns_message_test tests/dns_message_test.cpp src/dns_message.cpp)
target_include_directories(dns_message_test PRIVATE src/include)
target_compile_options(dns_message_test PRIVATE -Wall -Wextra -pedantic)
add_test(NAME dns_message_test COMMAND dns_message_test)

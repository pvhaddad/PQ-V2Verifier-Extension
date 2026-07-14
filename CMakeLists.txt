cmake_minimum_required(VERSION 3.20)
project(pq-v2verifier)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -pthread")

set(SOURCE_FILES
    src/main.cpp
    src/Vehicle.cpp
    src/v2vcrypto.cpp
    src/bsm.cpp
)
add_executable(${PROJECT_NAME} ${SOURCE_FILES})

target_include_directories(${PROJECT_NAME} PRIVATE ${PROJECT_SOURCE_DIR}/include)
target_include_directories(${PROJECT_NAME} PRIVATE $ENV{HOME}/liboqs-x86/include/)

target_link_libraries(${PROJECT_NAME} crypto $ENV{HOME}/liboqs-x86/lib/liboqs.a)

cmake_minimum_required(VERSION 3.10)
project(RemoteManagementFramework CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# 公共库
add_library(common STATIC
    common/common.cpp
    common/crypto.cpp
    common/protocol.cpp
)
target_include_directories(common PUBLIC ${CMAKE_SOURCE_DIR}/include)

# 服务端
add_executable(server server/server.cpp)
target_link_libraries(server common pthread)

# 客户端（Beacon）
add_executable(beacon beacon/beacon.cpp)
target_link_libraries(beacon common pthread)

# Windows 下链接 ws2_32
if(WIN32)
    target_link_libraries(server ws2_32)
    target_link_libraries(beacon ws2_32)
endif()

message(STATUS "Remote Management Framework 构建配置完成")

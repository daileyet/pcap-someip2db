cmake_minimum_required(VERSION 3.12)
project(pcap-someip2db)

# Set C++11
set(CMAKE_CXX_STANDARD 11)
# popen()/pclose() are not C++ standards
set(CMAKE_CXX_EXTENSIONS ON)
if(MSVC)
  set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} /Zi")
else()
  set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -g")
endif()

include_directories(
    ${CMAKE_CURRENT_SOURCE_DIR}/inc
)
file(GLOB cpp_src ./src/*.cpp)
file(GLOB c_src ./src/*.c)
add_executable("${PROJECT_NAME}" ${cpp_src} ${c_src})

if(NOT TARGET PcapPlusPlus::Pcap++)
  find_package(PcapPlusPlus REQUIRED)
endif()

target_link_libraries("${PROJECT_NAME}" PUBLIC PcapPlusPlus::Pcap++ SQLiteCpp sqlite3)
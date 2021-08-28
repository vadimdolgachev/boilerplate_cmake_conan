cmake_minimum_required(VERSION 3.20)
project(boilerplate_cmake_conan)

set(CMAKE_CXX_STANDARD 17)
add_compile_options(-Wall -Wextra -Wpedantic)

include(conan.cmake)

conan_cmake_configure(REQUIRES
        fmt/8.0.1
        boost/1.76.0
        GENERATORS cmake_find_package)
conan_cmake_install(PATH_OR_REFERENCE .
        BUILD missing
        REMOTE conan-center
        SETTINGS ${settings})

find_package(fmt REQUIRED)
find_package(OpenSSL COMPONENTS SSL REQUIRED)
find_package(Boost COMPONENTS system REQUIRED)

add_executable(${PROJECT_NAME} main.cpp root_certificates.hpp)
target_link_libraries(${PROJECT_NAME}
        fmt::fmt
        Boost::system
        OpenSSL::SSL)
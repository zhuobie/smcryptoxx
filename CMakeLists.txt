cmake_minimum_required(VERSION 3.5)
project(smcryptoxx)

if(MSYS)
    include(CMakeLists.msys.txt)
else()
    include(CMakeLists.unix.txt)
endif(MSYS)

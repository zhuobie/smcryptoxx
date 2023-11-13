cmake_minimum_required(VERSION 3.5)
project(smcryptoxx)

set(CMAKE_MACOSX_RPATH 1)
set(EXECUTABLE_OUTPUT_PATH ${PROJECT_BINARY_DIR}/bin)
set(LIBRARY_OUTPUT_PATH ${PROJECT_BINARY_DIR}/lib)

find_path(GMPXX_HEADER_PATH gmpxx.h)
find_path(TASN1_HEADER_PATH libtasn1.h)
include_directories(include ${GMPXX_HEADER_PATH} ${TASN1_HEADER_PATH})

set(CMAKE_FIND_LIBRARY_SUFFIXES ".a;.so")
find_library(GMPXX_LIB_STATIC_PATH gmpxx)
find_library(GMP_LIB_STATIC_PATH gmp)
find_library(TASN1_LIB_STATIC_PATH tasn1)
set(CMAKE_FIND_LIBRARY_SUFFIXES ".so;.a")
find_library(GMPXX_LIB_SHARED_PATH gmpxx)
find_library(GMP_LIB_SHARED_PATH gmp)
find_library(TASN1_LIB_SHARED_PATH tasn1)
add_library(smcryptoxx_static STATIC src/sm3.cpp src/sm4.cpp src/sm2.cpp src/utils.cpp)
add_library(smcryptoxx_shared SHARED src/sm3.cpp src/sm4.cpp src/sm2.cpp src/utils.cpp)
target_link_libraries(smcryptoxx_static ${GMPXX_LIB_STATIC_PATH} ${GMP_LIB_STATIC_PATH} ${TASN1_LIB_STATIC_PATH})
target_link_libraries(smcryptoxx_shared ${GMPXX_LIB_SHARED_PATH} ${GMP_LIB_SHARED_PATH} ${TASN1_LIB_SHARED_PATH})

set_target_properties(smcryptoxx_static PROPERTIES OUTPUT_NAME smcryptoxx)
set_target_properties(smcryptoxx_shared PROPERTIES VERSION 1.0 SOVERSION 1 OUTPUT_NAME smcryptoxx)

enable_testing()
add_subdirectory(tests)

install(DIRECTORY ${CMAKE_SOURCE_DIR}/include/smcryptoxx DESTINATION include)
install(TARGETS smcryptoxx_static smcryptoxx_shared ARCHIVE DESTINATION lib LIBRARY DESTINATION lib)
install(CODE "execute_process(COMMAND ldconfig)")

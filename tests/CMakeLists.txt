add_executable(test_sm2_static test_sm2.cpp)
add_executable(test_sm3_static test_sm3.cpp)
add_executable(test_sm4_static test_sm4.cpp)

add_executable(test_sm2_shared test_sm2.cpp)
add_executable(test_sm3_shared test_sm3.cpp)
add_executable(test_sm4_shared test_sm4.cpp)

target_link_libraries(test_sm2_static smcryptoxx_static)
target_link_libraries(test_sm3_static smcryptoxx_static)
target_link_libraries(test_sm4_static smcryptoxx_static)

target_link_libraries(test_sm2_shared smcryptoxx_shared)
target_link_libraries(test_sm3_shared smcryptoxx_shared)
target_link_libraries(test_sm4_shared smcryptoxx_shared)

include(CTest)

add_test(NAME test_sm2_static COMMAND test_sm2_static)
add_test(NAME test_sm3_static COMMAND test_sm3_static)
add_test(NAME test_sm4_static COMMAND test_sm4_static)

add_test(NAME test_sm2_shared COMMAND test_sm2_shared)
add_test(NAME test_sm3_shared COMMAND test_sm3_shared)
add_test(NAME test_sm4_shared COMMAND test_sm4_shared)

if(NOT MSYS)
    add_custom_command(TARGET test_sm4_shared POST_BUILD COMMAND ctest)
endif(NOT MSYS)

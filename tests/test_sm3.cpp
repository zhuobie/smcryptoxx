#include <iostream>
#include <string>
#include <vector>
#include <cassert>
#include "smcryptoxx/sm3.h"

int main() {
    std::vector<uint8_t> msg = {97, 98, 99};
    std::string msg_hash = sm3_hash(msg);
    assert(msg_hash == "66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0");
    std::string msg_string = "abc";
    std::string msg_string_hash = sm3_hash_string(msg_string);
    assert(msg_string_hash == "66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0");
    return 0;
}
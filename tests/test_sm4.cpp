#include <iostream>
#include <string>
#include <vector>
#include <cassert>
#include "smcryptoxx/sm4.h"

int main() {
    std::string key_1_str = "1234567812345678";
    std::vector<uint8_t> key_1(key_1_str.begin(), key_1_str.end());
    std::string iv_1_str = "0000000000000000";
    std::vector<uint8_t> iv_1(iv_1_str.begin(), iv_1_str.end());
    std::vector<uint8_t> data_1 = {97, 98, 99};
    std::string data_1_str = "abc";

    std::vector<uint8_t> encrypt_ecb_result = encrypt_ecb(data_1, key_1);
    std::vector<uint8_t> decrypt_ecb_result = decrypt_ecb(encrypt_ecb_result, key_1);
    assert(decrypt_ecb_result == data_1);

    std::string encrypt_ecb_string_result = encrypt_ecb_string(data_1_str, key_1_str);
    std::string decrypt_ecb_string_result = decrypt_ecb_string(encrypt_ecb_string_result, key_1_str);
    assert(decrypt_ecb_string_result == data_1_str);

    std::vector<uint8_t> encrypt_cbc_result = encrypt_cbc(data_1, key_1, iv_1);
    std::vector<uint8_t> decrypt_cbc_result = decrypt_cbc(encrypt_cbc_result, key_1, iv_1);
    assert(decrypt_cbc_result == data_1);

    std::string encrypt_cbc_string_result = encrypt_cbc_string(data_1_str, key_1_str, iv_1_str);
    std::string decrypt_cbc_string_result = decrypt_cbc_string(encrypt_cbc_string_result, key_1_str, iv_1_str);
    assert(decrypt_cbc_string_result == data_1_str);

    return 0;
}
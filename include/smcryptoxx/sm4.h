#ifndef SM4_H
#define SM4_H

#include "smcryptoxx/utils.h"

std::vector<uint8_t> encrypt_ecb(const std::vector<uint8_t>& p_input_data, const std::vector<uint8_t>& key);
std::string encrypt_ecb_string(const std::string& msg_string, const std::string& key);
std::vector<uint8_t> decrypt_ecb(const std::vector<uint8_t>& input_data, const std::vector<uint8_t>& key);
std::string decrypt_ecb_string(const std::string& msg_string, const std::string& key);
std::vector<uint8_t> encrypt_cbc(const std::vector<uint8_t>& p_input_data, const std::vector<uint8_t>& key, const std::vector<uint8_t>& p_iv);
std::string encrypt_cbc_string(const std::string& msg_string, const std::string& key, const std::string& iv);
std::vector<uint8_t> decrypt_cbc(const std::vector<uint8_t>& input_data, const std::vector<uint8_t>& key, const std::vector<uint8_t>& p_iv);
std::string decrypt_cbc_string(const std::string& msg_string, const std::string& key, const std::string& iv);

#endif
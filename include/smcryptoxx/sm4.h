#ifndef SM4_H
#define SM4_H

#include "smcryptoxx/utils.h"

std::vector<uint8_t> encrypt_ecb(const std::vector<uint8_t>& p_input_data, const std::vector<uint8_t>& key);
std::string encrypt_ecb_string(const std::string& msg_string, const std::string& key);
void encrypt_ecb_to_file(const std::string& data_path, const std::string& encrypt_path, const std::string& key);
std::vector<uint8_t> decrypt_ecb(const std::vector<uint8_t>& input_data, const std::vector<uint8_t>& key);
std::string decrypt_ecb_string(const std::string& msg_string, const std::string& key);
void decrypt_ecb_from_file(const std::string& encrypt_path, const std::string& data_path, const std::string& key);

std::vector<uint8_t> encrypt_cbc(const std::vector<uint8_t>& p_input_data, const std::vector<uint8_t>& key, const std::vector<uint8_t>& p_iv);
std::string encrypt_cbc_string(const std::string& msg_string, const std::string& key, const std::string& iv);
std::vector<uint8_t> decrypt_cbc(const std::vector<uint8_t>& input_data, const std::vector<uint8_t>& key, const std::vector<uint8_t>& p_iv);
std::string decrypt_cbc_string(const std::string& msg_string, const std::string& key, const std::string& iv);
void encrypt_cbc_to_file(const std::string& data_file, const std::string& encrypt_file, const std::string& key, const std::string& iv);
void decrypt_cbc_from_file(const std::string& encrypt_path, const std::string& data_path, const std::string& key, const std::string& iv);

#endif
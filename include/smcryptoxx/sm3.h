#ifndef SM3_H
#define SM3_H

#include "smcryptoxx/utils.h"

std::string sm3_hash(const std::vector<uint8_t>& p_msg);
std::string sm3_hash_string(const std::string& msg_string);
std::string sm3_hash_file(const std::string& file_path);

#endif
#ifndef UTILS_H
#define UTILS_H

#include <iostream>
#include <fstream>
#include <sstream>
#include <vector>
#include <string>
#include <algorithm>
#include <random>
#include <ctime>
#include <cmath>
#include <utility>
#include <chrono>
#include <bitset>
#include "libtasn1.h"
#include "gmpxx.h"

#define PARA_LEN 64
const std::string ENC_TABLE_BASE64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

void bytes_to_file(const std::vector<uint8_t>& file_bytes, const std::string& file_path);
std::vector<uint8_t> bytes_from_file(const std::string& file_path);
std::string random_hex(const size_t& size);
std::string format_hex(const std::string& hex_1, const std::string& hex_2);
std::string enc_base64(const std::vector<uint8_t>& byte_array);
std::vector<uint8_t> dec_base64(const std::string& base64_string);
std::vector<uint8_t> appendzero(const std::vector<uint8_t>& data, const size_t& size);
std::vector<uint8_t> removezero(const std::vector<uint8_t>& data, const size_t& size);
std::vector<uint8_t> u32_to_byte_array(const uint32_t& value);
uint32_t byte_array_to_u32(const std::vector<uint8_t>& byte_array);
std::vector<uint8_t> concvec(const std::vector<uint8_t>& p_vec_1, const std::vector<uint8_t>& vec_2);
std::string mpz_to_hex(const mpz_class& mpz);
mpz_class hex_to_mpz(const std::string& hex);
std::vector<uint8_t> mpz_to_byte_array(const mpz_class& mpz);
mpz_class byte_array_to_mpz(const std::vector<uint8_t>& byte_array);
std::vector<uint8_t> pad_zero_positive(const std::vector<uint8_t>& mpz_byte_array);
uint32_t rotate_left(const uint32_t& num, const uint32_t& shift);
uint32_t rotate_right(const uint32_t& num, const uint32_t& shift);
std::vector<uint8_t> to_be_bytes(const uint32_t& value);
uint32_t from_be_bytes(const std::vector<uint8_t>& byte_array);
std::string byte_array_to_hex(const std::vector<uint8_t>& byte_array);
std::vector<uint8_t> hex_to_byte_array(const std::string& hex_string);
std::vector<uint8_t> xor_vector(const std::vector<uint8_t>& a, const std::vector<uint8_t>& b);

#endif
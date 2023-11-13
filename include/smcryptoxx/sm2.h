#ifndef SM2_H
#define SM2_H

#if HAVE_CONFIG_H
#include "config.h"
#endif

#include "smcryptoxx/sm3.h"
#include "smcryptoxx/utils.h"

std::string gen_sk();
std::string pk_from_sk(const std::string& private_key);
bool pk_valid(const std::string& public_key);
std::vector<uint8_t> sk_to_sk_pem_bytes(const std::string& private_key);
std::string sk_from_sk_pem_bytes(const std::vector<uint8_t>& pem_bytes);
std::string pk_from_sk_pem_bytes(const std::vector<uint8_t>& pem_bytes);
std::vector<uint8_t> pk_to_pk_pem_bytes(const std::string& public_key);
std::string pk_from_pk_pem_bytes(const std::vector<uint8_t>& pem_bytes);

std::vector<uint8_t> sign_byte(const std::vector<uint8_t>& id, const std::vector<uint8_t>& data, const std::string& private_key);
bool verify_byte(const std::vector<uint8_t>& id, const std::vector<uint8_t>& data, const std::vector<uint8_t>& sign, const std::string& public_key);
std::string sign_string(const std::string& id, const std::string& data, const std::string& private_key);
bool verify_string(const std::string& id, const std::string& data, const std::string& sign_base64, const std::string& public_key);

std::vector<uint8_t> encrypt_byte(const std::vector<uint8_t>& data, const std::string& public_key);
std::vector<uint8_t> decrypt_byte(const std::vector<uint8_t>& asn1_encrypt_data, const std::string& private_key);
std::string encrypt_string(const std::string& data_string, const std::string& public_key);
std::string decrypt_string(const std::string& asn1_encrypt_data_base64, const std::string& private_key);

std::pair<std::string, std::string> keyexchange_1ab(const size_t& klen, const std::string& id, const std::string& private_key);
std::pair<std::string, std::string> keyexchange_2a(const std::string& id, const std::string& private_key, const std::string& private_key_r, const std::string& recive_from_b);
std::pair<std::string, std::string> keyexchange_2b(const std::string& id, const std::string& private_key, const std::string& private_key_r, const std::string& recive_from_a);

#endif
#include <iostream>
#include <string>
#include <vector>
#include <cassert>
#include "unistd.h"
#include "smcryptoxx/sm2.h"

int main() {
    std::string sk_1 = gen_sk();
    std::string sk_2 = gen_sk();
    std::string pk_1 = pk_from_sk(sk_1);
    std::string pk_2 = pk_from_sk(sk_2);
    assert(pk_valid(pk_1));
    assert(pk_valid(pk_2));
    std::vector<uint8_t> sk_1_pem_bytes = sk_to_sk_pem_bytes(sk_1);
    std::string sk_1_load = sk_from_sk_pem_bytes(sk_1_pem_bytes);
    assert(sk_1 == sk_1_load);
    std::string pk_1_load = pk_from_sk_pem_bytes(sk_1_pem_bytes);
    assert(pk_1 == pk_1_load);
    std::vector<uint8_t> pk_1_pem_bytes = pk_to_pk_pem_bytes(pk_1);
    pk_1_load = pk_from_pk_pem_bytes(pk_1_pem_bytes);
    assert(pk_1 == pk_1_load);

    std::string id_a = "id_a@company.com";
    std::string id_b = "id_b@company.com";
    std::vector<uint8_t> id_a_data(id_a.begin(), id_a.end());
    std::vector<uint8_t> id_b_data(id_b.begin(), id_b.end());
    std::vector<uint8_t> data_1 = {97, 98, 99};
    std::vector<uint8_t> sign_1 = sign_byte(id_a_data, data_1, sk_1);
    bool verify_1 = verify_byte(id_a_data, data_1, sign_1, pk_1);
    assert(verify_1);
    std::string sign_2 = sign_string(id_a, "abc", sk_1);
    bool verify_2 = verify_string(id_a, "abc", sign_2, pk_1);
    assert(verify_2);

    std::vector<uint8_t> encrypt_1 = encrypt_byte(data_1, pk_1);
    std::vector<uint8_t> decrypt_1 = decrypt_byte(encrypt_1, sk_1);
    assert(decrypt_1 == data_1);
    std::string encrypt_2 = encrypt_string("abc", pk_1);
    std::string decrypt_2 = decrypt_string(encrypt_2, sk_1);
    assert(decrypt_2 == "abc");
    
    return 0;
}

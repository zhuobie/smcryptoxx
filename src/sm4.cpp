#include "smcryptoxx/sm4.h"

const uint8_t SM4_BOXES_TABLE[] = {
    0xd6, 0x90, 0xe9, 0xfe, 0xcc, 0xe1, 0x3d, 0xb7, 0x16, 0xb6, 0x14, 0xc2, 0x28, 0xfb, 0x2c, 
    0x05, 0x2b, 0x67, 0x9a, 0x76, 0x2a, 0xbe, 0x04, 0xc3, 0xaa, 0x44, 0x13, 0x26, 0x49, 0x86, 
    0x06, 0x99, 0x9c, 0x42, 0x50, 0xf4, 0x91, 0xef, 0x98, 0x7a, 0x33, 0x54, 0x0b, 0x43, 0xed, 
    0xcf, 0xac, 0x62, 0xe4, 0xb3, 0x1c, 0xa9, 0xc9, 0x08, 0xe8, 0x95, 0x80, 0xdf, 0x94, 0xfa, 
    0x75, 0x8f, 0x3f, 0xa6, 0x47, 0x07, 0xa7, 0xfc, 0xf3, 0x73, 0x17, 0xba, 0x83, 0x59, 0x3c, 
    0x19, 0xe6, 0x85, 0x4f, 0xa8, 0x68, 0x6b, 0x81, 0xb2, 0x71, 0x64, 0xda, 0x8b, 0xf8, 0xeb, 
    0x0f, 0x4b, 0x70, 0x56, 0x9d, 0x35, 0x1e, 0x24, 0x0e, 0x5e, 0x63, 0x58, 0xd1, 0xa2, 0x25, 
    0x22, 0x7c, 0x3b, 0x01, 0x21, 0x78, 0x87, 0xd4, 0x00, 0x46, 0x57, 0x9f, 0xd3, 0x27, 0x52, 
    0x4c, 0x36, 0x02, 0xe7, 0xa0, 0xc4, 0xc8, 0x9e, 0xea, 0xbf, 0x8a, 0xd2, 0x40, 0xc7, 0x38, 
    0xb5, 0xa3, 0xf7, 0xf2, 0xce, 0xf9, 0x61, 0x15, 0xa1, 0xe0, 0xae, 0x5d, 0xa4, 0x9b, 0x34, 
    0x1a, 0x55, 0xad, 0x93, 0x32, 0x30, 0xf5, 0x8c, 0xb1, 0xe3, 0x1d, 0xf6, 0xe2, 0x2e, 0x82, 
    0x66, 0xca, 0x60, 0xc0, 0x29, 0x23, 0xab, 0x0d, 0x53, 0x4e, 0x6f, 0xd5, 0xdb, 0x37, 0x45, 
    0xde, 0xfd, 0x8e, 0x2f, 0x03, 0xff, 0x6a, 0x72, 0x6d, 0x6c, 0x5b, 0x51, 0x8d, 0x1b, 0xaf, 
    0x92, 0xbb, 0xdd, 0xbc, 0x7f, 0x11, 0xd9, 0x5c, 0x41, 0x1f, 0x10, 0x5a, 0xd8, 0x0a, 0xc1, 
    0x31, 0x88, 0xa5, 0xcd, 0x7b, 0xbd, 0x2d, 0x74, 0xd0, 0x12, 0xb8, 0xe5, 0xb4, 0xb0, 0x89, 
    0x69, 0x97, 0x4a, 0x0c, 0x96, 0x77, 0x7e, 0x65, 0xb9, 0xf1, 0x09, 0xc5, 0x6e, 0xc6, 0x84, 
    0x18, 0xf0, 0x7d, 0xec, 0x3a, 0xdc, 0x4d, 0x20, 0x79, 0xee, 0x5f, 0x3e, 0xd7, 0xcb, 0x39, 
    0x48
};

const uint32_t SM4_FK[] = {0xa3b1bac6, 0x56aa3350, 0x677d9197, 0xb27022dc};

const uint32_t SM4_CK[] = {
    0x00070e15, 0x1c232a31, 0x383f464d, 0x545b6269, 
    0x70777e85, 0x8c939aa1, 0xa8afb6bd, 0xc4cbd2d9, 
    0xe0e7eef5, 0xfc030a11, 0x181f262d, 0x343b4249, 
    0x50575e65, 0x6c737a81, 0x888f969d, 0xa4abb2b9, 
    0xc0c7ced5, 0xdce3eaf1, 0xf8ff060d, 0x141b2229, 
    0x30373e45, 0x4c535a61, 0x686f767d, 0x848b9299, 
    0xa0a7aeb5, 0xbcc3cad1, 0xd8dfe6ed, 0xf4fb0209, 
    0x10171e25, 0x2c333a41, 0x484f565d, 0x646b7279
};

uint32_t round_key(const uint32_t& ka) {
    std::vector<uint8_t> b = {0, 0, 0, 0};
    std::vector<uint8_t> a = to_be_bytes(ka);
    b[0] = SM4_BOXES_TABLE[a[0]];
    b[1] = SM4_BOXES_TABLE[a[1]];
    b[2] = SM4_BOXES_TABLE[a[2]];
    b[3] = SM4_BOXES_TABLE[a[3]];
    uint32_t bb = from_be_bytes(b);
    uint32_t rk = bb ^ rotate_left(bb, 13) ^ rotate_left(bb, 23);
    return rk;
}

uint32_t sm4_l_t(const uint32_t& ka) {
    std::vector<uint8_t> b = {0, 0, 0, 0};
    std::vector<uint8_t> a = to_be_bytes(ka);
    b[0] = SM4_BOXES_TABLE[a[0]];
    b[1] = SM4_BOXES_TABLE[a[1]];
    b[2] = SM4_BOXES_TABLE[a[2]];
    b[3] = SM4_BOXES_TABLE[a[3]];
    uint32_t bb = from_be_bytes(b);
    return bb ^ rotate_left(bb, 2) ^ rotate_left(bb, 10) ^ rotate_left(bb, 18) ^ rotate_left(bb, 24);
}

uint32_t f(const uint32_t& x0, const uint32_t& x1, const uint32_t& x2, const uint32_t& x3, const uint32_t& rk) {
    return x0 ^ sm4_l_t(x1 ^ x2 ^ x3 ^ rk);
}

std::vector<uint8_t> padding(const std::vector<uint8_t>& data) {
    std::vector<uint8_t> result = data;
    std::vector<uint8_t> append;
    std::fill_n(std::back_inserter(append), 16 - data.size() % 16, 16 - data.size() % 16);
    for (uint8_t i: append) {
        result.push_back(i);
    }
    return result;
}

std::vector<uint8_t> unpadding(const std::vector<uint8_t>& data) {
    std::vector<uint8_t> slice(data.begin(), data.begin() + (data.size() - data[data.size() - 1]));
    return slice;
}

std::vector<uint32_t> set_key(const std::vector<uint8_t>& key, const std::string& mode) {
    std::vector<uint32_t> sk;
    std::fill_n(std::back_inserter(sk), 32, 0);
    std::vector<uint32_t> mk = {0, 0, 0, 0};
    std::vector<uint32_t> k;
    std::fill_n(std::back_inserter(k), 36, 0);
    std::vector<uint8_t> mk_0(key.begin(), key.begin() + 4);
    std::vector<uint8_t> mk_1(key.begin() + 4, key.begin() + 8);
    std::vector<uint8_t> mk_2(key.begin() + 8, key.begin() + 12);
    std::vector<uint8_t> mk_3(key.begin() + 12, key.begin() + 16);
    mk[0] = from_be_bytes(mk_0);
    mk[1] = from_be_bytes(mk_1);
    mk[2] = from_be_bytes(mk_2);
    mk[3] = from_be_bytes(mk_3);
    for (int i = 0; i < 4; i++) {
        k[i] = mk[i] ^ SM4_FK[i];
    }
    for (int i = 0; i < 32; i++) {
        k[i + 4] = k[i] ^ (round_key(k[i + 1] ^ k[i + 2] ^ k[i + 3] ^ SM4_CK[i]));
        sk[i] = k[i + 4];
    }
    if (mode == "SM4_DECRYPT") {
        for (int idx = 0; idx < 16; idx++) {
            uint32_t t = sk[idx];
            sk[idx] = sk[31 - idx];
            sk[31 - idx] = t;
        }
    }
    return sk;
}

std::vector<uint8_t> one_round(const std::vector<uint32_t>& sk, const std::vector<uint8_t>& in_put) {
    std::vector<uint8_t> out_put;
    std::vector<uint32_t> ulbuf;
    std::fill_n(std::back_inserter(ulbuf), 36, 0);
    std::vector<uint8_t> ulbuf_0(in_put.begin(), in_put.begin() + 4);
    std::vector<uint8_t> ulbuf_1(in_put.begin() + 4, in_put.begin() + 8);
    std::vector<uint8_t> ulbuf_2(in_put.begin() + 8, in_put.begin() + 12);
    std::vector<uint8_t> ulbuf_3(in_put.begin() + 12, in_put.begin() + 16);
    ulbuf[0] = from_be_bytes(ulbuf_0);
    ulbuf[1] = from_be_bytes(ulbuf_1);
    ulbuf[2] = from_be_bytes(ulbuf_2);
    ulbuf[3] = from_be_bytes(ulbuf_3);
    for (int idx = 0; idx < 32; idx++) {
        ulbuf[idx + 4] = f(ulbuf[idx], ulbuf[idx + 1], ulbuf[idx + 2], ulbuf[idx + 3], sk[idx]);
    }
    for (uint8_t i: to_be_bytes(ulbuf[35])) {
        out_put.push_back(i);
    }
    for (uint8_t i: to_be_bytes(ulbuf[34])) {
        out_put.push_back(i);
    }
    for (uint8_t i: to_be_bytes(ulbuf[33])) {
        out_put.push_back(i);
    }
    for (uint8_t i: to_be_bytes(ulbuf[32])) {
        out_put.push_back(i);
    }
    return out_put;
}

std::vector<uint8_t> encrypt_ecb(const std::vector<uint8_t>& p_input_data, const std::vector<uint8_t>& key) {
    std::vector<uint8_t> input_data = p_input_data;
    std::vector<uint32_t> sk = set_key(key, "SM4_ENCRYPT");
    input_data = padding(input_data);
    size_t length = input_data.size();
    size_t i = 0;
    std::vector<uint8_t> output_data;
    while (length > 0) {
        std::vector<uint8_t> input_data_16(input_data.begin() + i, input_data.begin() + (i + 16));
        for (uint8_t j: one_round(sk, input_data_16)) {
            output_data.push_back(j);
        }
        i += 16;
        length -= 16;
    }
    return output_data;
}

std::string encrypt_ecb_string(const std::string& msg_string, const std::string& key) {
    std::vector<uint8_t> msg_byte_array(msg_string.begin(), msg_string.end());
    std::vector<uint8_t> key_byte_array(key.begin(), key.end());
    std::vector<uint8_t> encrypted_ecb_byte_array = encrypt_ecb(msg_byte_array, key_byte_array);
    return byte_array_to_hex(encrypted_ecb_byte_array);
}

std::vector<uint8_t> decrypt_ecb(const std::vector<uint8_t>& input_data, const std::vector<uint8_t>& key) {
    std::vector<uint32_t> sk = set_key(key, "SM4_DECRYPT");
    size_t length = input_data.size();
    size_t i = 0;
    std::vector<uint8_t> output_data;
    while (length > 0) {
        std::vector<uint8_t> input_data_16(input_data.begin() + i, input_data.begin() + (i + 16));
        for (uint8_t j: one_round(sk, input_data_16)) {
            output_data.push_back(j);
        }
        i += 16;
        length -= 16;
    }
    return unpadding(output_data);
}

std::string decrypt_ecb_string(const std::string& msg_string, const std::string& key) {
    std::vector<uint8_t> msg_byte_array = hex_to_byte_array(msg_string);
    std::vector<uint8_t> key_byte_array(key.begin(), key.end());
    std::vector<uint8_t> decrypted_byte_array = decrypt_ecb(msg_byte_array, key_byte_array);
    std::string decrypted_string(decrypted_byte_array.begin(), decrypted_byte_array.end());
    return decrypted_string;
}

std::vector<uint8_t> encrypt_cbc(const std::vector<uint8_t>& p_input_data, const std::vector<uint8_t>& key, const std::vector<uint8_t>& p_iv) {
    std::vector<uint8_t> iv = p_iv;
    std::vector<uint8_t> input_data = p_input_data;
    std::vector<uint32_t> sk = set_key(key, "SM4_ENCRYPT");
    size_t i = 0;
    std::vector<uint8_t> output_data;
    std::vector<uint8_t> tmp_input;
    input_data = padding(input_data);
    size_t length = input_data.size();
    while (length > 0) {
        std::vector<uint8_t> input_data_16(input_data.begin() + i, input_data.begin() + (i + 16));
        std::vector<uint8_t> iv_16(iv.begin(), iv.begin() + 16);
        tmp_input = xor_vector(input_data_16, iv_16);
        std::vector<uint8_t> tmp_input_16(tmp_input.begin(), tmp_input.begin() + 16);
        for (uint8_t j: one_round(sk, tmp_input_16)) {
            output_data.push_back(j);
        }
        std::vector<uint8_t> iv_tmp(output_data.begin() + i, output_data.begin() + (i + 16));
        iv = iv_tmp;
        i += 16;
        length -= 16;
    }
    return output_data;
}

std::string encrypt_cbc_string(const std::string& msg_string, const std::string& key, const std::string& iv) {
    std::vector<uint8_t> msg_byte_array(msg_string.begin(), msg_string.end());
    std::vector<uint8_t> key_byte_array(key.begin(), key.end());
    std::vector<uint8_t> iv_byte_array(iv.begin(), iv.end());
    std::vector<uint8_t> encrypted_cbc_byte_array = encrypt_cbc(msg_byte_array, key_byte_array, iv_byte_array);
    return byte_array_to_hex(encrypted_cbc_byte_array);
}

std::vector<uint8_t> decrypt_cbc(const std::vector<uint8_t>& input_data, const std::vector<uint8_t>& key, const std::vector<uint8_t>& p_iv) {
    std::vector<uint8_t> iv = p_iv;
    std::vector<uint32_t> sk = set_key(key, "SM4_DECRYPT");
    size_t i = 0;
    std::vector<uint8_t> output_data;
    size_t length = input_data.size();
    while (length > 0) {
        std::vector<uint8_t> input_data_16(input_data.begin() + i, input_data.begin() + (i + 16));
        for (uint8_t j: one_round(sk, input_data_16)) {
            output_data.push_back(j);
        }
        std::vector<uint8_t> output_data_16(output_data.begin() + i, output_data.begin() + (i + 16));
        std::vector<uint8_t> iv_16(iv.begin(), iv.begin() + 16);
        std::vector<uint8_t> tmp_copy = xor_vector(output_data_16, iv_16);
        std::copy(tmp_copy.begin(), tmp_copy.end(), output_data.begin() + i);
        std::vector<uint8_t> iv_tmp(input_data.begin() + i, input_data.begin() + (i + 16));
        iv = iv_tmp;
        i += 16;
        length -= 16;
    }
    return unpadding(output_data);
}

std::string decrypt_cbc_string(const std::string& msg_string, const std::string& key, const std::string& iv) {
    std::vector<uint8_t> msg_byte_array = hex_to_byte_array(msg_string);
    std::vector<uint8_t> key_byte_array(key.begin(), key.end());
    std::vector<uint8_t> iv_byte_array(iv.begin(), iv.end());
    std::vector<uint8_t> decrypted_byte_array = decrypt_cbc(msg_byte_array, key_byte_array, iv_byte_array);
    std::string decrypted_string(decrypted_byte_array.begin(), decrypted_byte_array.end());
    return decrypted_string;
}

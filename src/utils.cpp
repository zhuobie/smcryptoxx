#include "smcryptoxx/utils.h"

void bytes_to_file(const std::vector<uint8_t>& file_bytes, const std::string& file_path) {
    std::ofstream output_file(file_path, std::ios::binary | std::ios::out);
    output_file.write(reinterpret_cast<const char*>(file_bytes.data()), file_bytes.size());
    output_file.close();
}

std::vector<uint8_t> bytes_from_file(const std::string& file_path) {
    std::ifstream input_file(file_path, std::ios::binary);
    std::vector<uint8_t> file_bytes((std::istreambuf_iterator<char>(input_file)), std::istreambuf_iterator<char>());
    input_file.close();
    return file_bytes;
}

std::string random_hex(const size_t& size) {
    std::vector<std::string> c = {"0", "1", "2", "3", "4", "5", "6", "7", "8", "9", "a", "b", "c", "d", "e", "f"};
    auto seed = std::chrono::high_resolution_clock::now().time_since_epoch().count();
    std::mt19937 rng(seed);
    std::uniform_int_distribution<int> distribution(0, c.size() - 1);
    int random_idx;
    std::string random_hex, result;
    for (size_t i = 0; i < size; i++) {
        random_idx = distribution(rng);
        random_hex = c[random_idx];
        result.append(random_hex);
    }
    return result;
}

std::string format_hex(const std::string& hex_1, const std::string& hex_2) {
    std::string hex_1_pad = std::string(PARA_LEN - hex_1.size(), '0') + hex_1;
    std::string hex_2_pad = std::string(PARA_LEN - hex_2.size(), '0') + hex_2;
    return hex_1_pad + hex_2_pad;
}

std::string enc_base64_group(const std::vector<uint8_t>& byte_array) {
    std::string bit_string;
    for (size_t i = 0; i < byte_array.size(); i++) {
        std::bitset<8> bits(byte_array[i]);
        bit_string += bits.to_string();
    }
    std::string result_base64;
    if (byte_array.size() == 3) {
        for (int i = 0; i < 24; i+=6) {
            std::bitset<8> binary(bit_string.substr(i, 6));
            result_base64 += ENC_TABLE_BASE64[binary.to_ulong()];
        }
    }
    if (byte_array.size() == 2) {
        bit_string += "00";
        for (int i = 0; i < 18; i+=6) {
            std::bitset<8> binary(bit_string.substr(i, 6));
            result_base64 += ENC_TABLE_BASE64[binary.to_ulong()];
        }
        result_base64 += "=";
    }
    if (byte_array.size() == 1) {
        bit_string += "0000";
        for (int i = 0; i < 12; i+=6) {
            std::bitset<8> binary(bit_string.substr(i, 6));
            result_base64 += ENC_TABLE_BASE64[binary.to_ulong()];
        }
        result_base64 += "==";
    }
    return result_base64;
}

std::vector<uint8_t> dec_base64_group(const std::string& base64_string) {
    std::vector<uint8_t> result_base64;
    std::string bit_string;
    if (base64_string[3] != '=') {
        for (int i = 0; i < 4; i++) {
            std::bitset<6> binary_6(ENC_TABLE_BASE64.find(base64_string[i]));
            bit_string += binary_6.to_string();
        }
        for (int i = 0; i < 24; i+=8) {
            std::bitset<8> binary_8(bit_string.substr(i, 8));
            result_base64.push_back(binary_8.to_ulong());
        }
    }
    if (base64_string[3] == '=' && base64_string[2] != '=') {
        for (int i = 0; i < 3; i++) {
            std::bitset<6> binary_6(ENC_TABLE_BASE64.find(base64_string[i]));
            bit_string += binary_6.to_string();
        }
        for (int i = 0; i < 16; i+=8) {
            std::bitset<8> binary_8(bit_string.substr(i, 8));
            result_base64.push_back(binary_8.to_ulong());
        }
    }
    if (base64_string[3] == '=' && base64_string[2] == '=') {
        for (int i = 0; i < 2; i++) {
            std::bitset<6> binary_6(ENC_TABLE_BASE64.find(base64_string[i]));
            bit_string += binary_6.to_string();
        }
        for (int i = 0; i < 8; i+=8) {
            std::bitset<8> binary_8(bit_string.substr(i, 8));
            result_base64.push_back(binary_8.to_ulong());
        }
    }
    return result_base64;
}

std::string enc_base64(const std::vector<uint8_t>& byte_array) {
    std::string result_base64;
    if (byte_array.size() % 3 == 0) {
        for (size_t i = 0; i < byte_array.size(); i+=3) {
            std::vector<uint8_t> byte_array_slice(byte_array.begin() + i, byte_array.begin() + i + 3);
            result_base64 += enc_base64_group(byte_array_slice);
        }
    }
    if (byte_array.size() % 3 == 2) {
        for (size_t i = 0; i < byte_array.size() - 2; i+=3) {
            std::vector<uint8_t> byte_array_slice(byte_array.begin() + i, byte_array.begin() + i + 3);
            result_base64 += enc_base64_group(byte_array_slice);
        }
        std::vector<uint8_t> byte_array_last(byte_array.end() - 2, byte_array.end());
        result_base64 += enc_base64_group(byte_array_last);
    }
    if (byte_array.size() % 3 == 1) {
        for (size_t i = 0; i < byte_array.size() - 1; i+=3) {
            std::vector<uint8_t> byte_array_slice(byte_array.begin() + i, byte_array.begin() + i + 3);
            result_base64 += enc_base64_group(byte_array_slice);
        }
        std::vector<uint8_t> byte_array_last(byte_array.end() - 1, byte_array.end());
        result_base64 += enc_base64_group(byte_array_last);
    }
    return result_base64;
}

std::vector<uint8_t> dec_base64(const std::string& base64_string) {
    std::vector<uint8_t> base64_result;
    for (size_t i = 0; i < base64_string.size(); i+=4) {
        std::vector<uint8_t> dec_base64_group_i = dec_base64_group(base64_string.substr(i, 4));
        base64_result.insert(base64_result.end(), dec_base64_group_i.begin(), dec_base64_group_i.end());
    }
    return base64_result;
}

std::vector<uint8_t> appendzero(const std::vector<uint8_t>& data, const size_t& size) {
    if (data.size() < size) {
        std::vector<uint8_t> zeroslice(size - data.size(), 0);
        zeroslice.insert(zeroslice.end(), data.begin(), data.end());
        return zeroslice;
    } else {
        return data;
    }
}

std::vector<uint8_t> removezero(const std::vector<uint8_t>& data, const size_t& size) {
    if (data.size() > size) {
        std::vector<uint8_t> remainslice(data.end() - size, data.end());
        return remainslice;
    } else {
        return data;
    }
}

std::vector<uint8_t> u32_to_byte_array(const uint32_t& value) {
    std::vector<uint8_t> byte_array(4, 0);
    byte_array[0] = (value >> 24) & 0xFF;
    byte_array[1] = (value >> 16) & 0xFF;
    byte_array[2] = (value >> 8) & 0xFF;
    byte_array[3] = value & 0xFF;
    return byte_array;
}

uint32_t byte_array_to_u32(const std::vector<uint8_t>& byte_array) {
    uint32_t value = 0;
    value |= static_cast<uint32_t>(byte_array[0]) << 24;
    value |= static_cast<uint32_t>(byte_array[1]) << 16;
    value |= static_cast<uint32_t>(byte_array[2]) << 8;
    value |= static_cast<uint32_t>(byte_array[3]);
    return value;
}

std::vector<uint8_t> concvec(const std::vector<uint8_t>& p_vec_1, const std::vector<uint8_t>& vec_2) {
    std::vector<uint8_t> vec_1 = p_vec_1;
    vec_1.insert(vec_1.end(), vec_2.begin(), vec_2.end());
    return vec_1;
}

std::string mpz_to_hex(const mpz_class& mpz) {
    char* cstr = mpz_get_str(NULL, 16, mpz.get_mpz_t());
    std::string hex(cstr);
    free(cstr);
    return hex;
}

mpz_class hex_to_mpz(const std::string& hex) {
    mpz_class mpz;
    mpz_set_str(mpz.get_mpz_t(), hex.c_str(), 16);
    return mpz;
}

std::vector<uint8_t> mpz_to_byte_array(const mpz_class& mpz) {
    size_t size = (mpz_sizeinbase(mpz.get_mpz_t(), 2) + 7) / 8;
    std::vector<uint8_t> byte_array(size);
    mpz_export(byte_array.data(), NULL, 1, sizeof(byte_array[0]), 1, 0, mpz.get_mpz_t());
    return byte_array;
}

mpz_class byte_array_to_mpz(const std::vector<uint8_t>& byte_array) {
    mpz_class mpz;
    mpz_import(mpz.get_mpz_t(), byte_array.size(), 1, sizeof(byte_array[0]), 1, 0, byte_array.data());
    return mpz;
}

std::vector<uint8_t> pad_zero_positive(const std::vector<uint8_t>& mpz_byte_array) {
    std::vector<uint8_t> result = mpz_byte_array;
    auto byte_to_binary = [](uint8_t b) {
        std::string b_string = "";
        for (int i = 7; i >= 0; i--) {
            b_string += std::to_string((b >> i) & 1);
        }
        return b_string;
    };
    char msb = byte_to_binary(mpz_byte_array[0])[0];
    if (msb == '1') {
        result.insert(result.begin(), 0);
    }
    return result;
}

uint32_t rotate_left(const uint32_t& num, const uint32_t& shift) {
    return (num << shift) | (num >> (32 - shift));
}

uint32_t rotate_right(const uint32_t& num, const uint32_t& shift) {
    return (num >> shift) | (num << (32 - shift));
}

std::vector<uint8_t> to_be_bytes(const uint32_t& value) {
    std::vector<uint8_t> byte_array(4);
    byte_array[0] = (value >> 24) & 0xff;
    byte_array[1] = (value >> 16) & 0xff;
    byte_array[2] = (value >> 8) & 0xff;
    byte_array[3] = value & 0xff;
    return byte_array;
}

uint32_t from_be_bytes(const std::vector<uint8_t>& byte_array) {
    uint32_t value = 0;
    value |= byte_array[0] << 24;
    value |= byte_array[1] << 16;
    value |= byte_array[2] << 8;
    value |= byte_array[3];
    return value;
}

std::string byte_array_to_hex(const std::vector<uint8_t>& byte_array) {
    std::string hex_chars = "0123456789abcdef";
    std::string hex_string;
    for (uint8_t byte: byte_array) {
        hex_string += hex_chars[byte >> 4];
        hex_string += hex_chars[byte & 0x0F];
    }
    return hex_string;
}

std::vector<uint8_t> hex_to_byte_array(const std::string& hex_string) {
    std::vector<uint8_t> byte_array;
    auto hex_to_byte = [](const char& hex_char) -> uint8_t {
        if (hex_char >= '0' && hex_char <= '9') {
            return hex_char - '0';
        } else if (hex_char >= 'a' && hex_char <= 'f') {
            return hex_char - 'a' + 10;
        } else if (hex_char >= 'A' && hex_char <= 'F') {
            return hex_char - 'A' + 10;
        } else {
            return 0;
        }
    };
    for (size_t i = 0; i < hex_string.size(); i+= 2) {
        uint8_t high_nibble = hex_to_byte(hex_string[i]);
        uint8_t low_nibble = hex_to_byte(hex_string[i + 1]);
        uint8_t byte = (high_nibble << 4) | low_nibble;
        byte_array.push_back(byte);
    }
    return byte_array;
}

std::vector<uint8_t> xor_vector(const std::vector<uint8_t>& a, const std::vector<uint8_t>& b) {
    std::vector<uint8_t> c;
    for (int i = 0; i < static_cast<int>(a.size()); i++) {
        c.push_back(a[i] ^ b[i]);
    }
    return c;
}

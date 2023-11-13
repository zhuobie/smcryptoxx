#include "smcryptoxx/sm3.h"

uint32_t sm3_ff_j(const uint32_t& x, const uint32_t& y, const uint32_t& z, const uint32_t& j) {
    uint32_t ret = 0;
    if (j < 16) {
        ret = x ^ y ^ z;
    } else if (16 <= j && j < 64) {
        ret = (x & y) | (x & z) | (y & z);
    }
    return ret;
}

uint32_t sm3_gg_j(const uint32_t& x, const uint32_t& y, const uint32_t& z, const uint32_t& j) {
    uint32_t ret = 0;
    if (j < 16) {
        ret = x ^ y ^ z;
    } else if (16 <= j && j < 64) {
        ret = (x & y) | (~x & z);
    }
    return ret;
}

uint32_t sm3_p_0(const uint32_t& x) {
    return x ^ rotate_left(x, 9) ^ rotate_left(x, 17);
}

uint32_t sm3_p_1(const uint32_t& x) {
    return x ^ rotate_left(x, 15) ^ rotate_left(x, 23);
}

std::vector<uint32_t> sm3_cf(const std::vector<uint32_t>& v_i, const std::vector<uint32_t>& b_i) {
    std::vector<uint32_t> t_j = {
        2043430169, 2043430169, 2043430169, 2043430169, 2043430169, 2043430169,
        2043430169, 2043430169, 2043430169, 2043430169, 2043430169, 2043430169,
        2043430169, 2043430169, 2043430169, 2043430169, 2055708042, 2055708042,
        2055708042, 2055708042, 2055708042, 2055708042, 2055708042, 2055708042,
        2055708042, 2055708042, 2055708042, 2055708042, 2055708042, 2055708042,
        2055708042, 2055708042, 2055708042, 2055708042, 2055708042, 2055708042,
        2055708042, 2055708042, 2055708042, 2055708042, 2055708042, 2055708042,
        2055708042, 2055708042, 2055708042, 2055708042, 2055708042, 2055708042,
        2055708042, 2055708042, 2055708042, 2055708042, 2055708042, 2055708042,
        2055708042, 2055708042, 2055708042, 2055708042, 2055708042, 2055708042,
        2055708042, 2055708042, 2055708042, 2055708042
    };
    std::vector<uint32_t> w;
    for (uint32_t i = 0; i < 16; i++) {
        uint32_t weight = 0x1000000;
        uint32_t data = 0;
        for (uint32_t k = (i * 4); k < (i * 4 + 4); k++) {
            data += (b_i[k] * weight);
            weight /= 0x100;
        }
        w.push_back(data);
    }
    for (uint32_t j = 16; j < 68; j++) {
        w.push_back(0);
        w[j] = sm3_p_1(w[j - 16] ^ w[j - 9] ^ rotate_left(w[j - 3], 15)) ^ rotate_left(w[j - 13], 7) ^ w[j - 6];
    }
    std::vector<uint32_t> w_1;
    for (uint32_t j = 0; j < 64; j++) {
        w_1.push_back(0);
        w_1[j] = w[j] ^ w[j + 4];
    }
    uint32_t a = v_i[0];
    uint32_t b = v_i[1];
    uint32_t c = v_i[2];
    uint32_t d = v_i[3];
    uint32_t e = v_i[4];
    uint32_t f = v_i[5];
    uint32_t g = v_i[6];
    uint32_t h = v_i[7];
    for (uint32_t j = 0; j < 64; j++) {
        uint32_t ss_1 = rotate_left((rotate_left(a, 12) + e + rotate_left(t_j[j], j)) & 0xffffffff, 7);
        uint32_t ss_2 = ss_1 ^ rotate_left(a, 12);
        uint32_t tt_1 = (sm3_ff_j(a, b, c, j) + d + ss_2 + w_1[j]) & 0xffffffff;
        uint32_t tt_2 = (sm3_gg_j(e, f, g, j) + h + ss_1 + w[j]) & 0xffffffff;
        d = c;
        c = rotate_left(b, 9);
        b = a;
        a = tt_1;
        h = g;
        g = rotate_left(f, 19);
        f = e;
        e = sm3_p_0(tt_2);
        a = a & 0xffffffff;
        b = b & 0xffffffff;
        c = c & 0xffffffff;
        d = d & 0xffffffff;
        e = e & 0xffffffff;
        f = f & 0xffffffff;
        g = g & 0xffffffff;
        h = h & 0xffffffff;
    }
    std::vector<uint32_t> v_j = {a, b, c, d, e, f, g, h};
    std::vector<uint32_t> cf;
    for (uint32_t i = 0; i < 8; i++) {
        cf.push_back(v_j[i] ^ v_i[i]);
    }
    return cf;
}

std::string sm3_hash(const std::vector<uint8_t>& p_msg) {
    std::vector<uint8_t> msg = p_msg;
    std::vector<uint32_t> iv = {
        1937774191, 1226093241, 388252375, 3666478592,
        2842636476, 372324522, 3817729613, 2969243214
    };
    uint32_t len1 = msg.size();
    uint32_t reverse1 = len1 % 64;
    msg.push_back(0x80);
    reverse1 += 1;
    uint32_t range_end = 56;
    if (reverse1 > range_end) {
        range_end += 64;
    }
    for (uint32_t i = reverse1; i < range_end; i++) {
        msg.push_back(0x00);
    }
    size_t bit_length = len1 * 8;
    std::vector<size_t> bit_length_str = {bit_length % 0x100};
    for (uint32_t i = 0; i < 7; i++) {
        bit_length /= 0x100;
        bit_length_str.push_back(bit_length % 0x100);
    }
    for (uint32_t i = 0; i < 8; i++) {
        msg.push_back(uint8_t(bit_length_str[7 - i]));
    }
    size_t group_count = round((double)msg.size() / (double)64);
    std::vector<std::vector<uint32_t>> b;
    for (uint32_t i = 0; i < group_count; i++) {
        std::vector<uint32_t> v_p(msg.begin() + (i * 64), msg.begin() + (i * 64 + 64));
        b.push_back(v_p);
    }
    std::vector<std::vector<uint32_t>> v;
    v.push_back(iv);
    for (uint32_t i = 0; i < group_count; i++) {
        v.push_back(sm3_cf(v[i], b[i]));
    }
    std::vector<uint32_t> y = v[group_count];

    std::string result = "";
    for (uint32_t i = 0; i < static_cast<uint32_t>(y.size()); i ++) {
        std::stringstream ss;
        ss << std::hex << y[i];
        std::string result_i = ss.str();
        while (result_i.length() < 8) {
            result_i = "0" + result_i;
        }
        result += result_i;
    }
    return result;
}

std::string sm3_hash_string(const std::string& msg_string) {
    std::vector<uint8_t> msg_bytes(msg_string.begin(), msg_string.end());
    std::string result_hash = sm3_hash(msg_bytes);
    return result_hash;
}

#include "smcryptoxx/sm2.h"

const std::string ECC_N = "FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123";
const std::string ECC_P = "FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF";
const std::string ECC_G = "32c4ae2c1f1981195f9904466a39c9948fe30bbff2660be1715a4589334c74c7bc3736a2f4f6779c59bdcee36b692153d0a9877cc62a474002df32e52139f0a0";
const std::string ECC_A = "FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC";
const std::string ECC_B = "28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93";

const asn1_static_node sequence_asn1_tab_sign[] = {
  { "SEQUENCERS", 536875024, NULL },
  { NULL, 1073741836, NULL },
  { "SequenceOfRS", 536870917, NULL },
  { "r", 1073741827, NULL },
  { "s", 3, NULL },
  { NULL, 0, NULL }
};

const asn1_static_node sequence_asn1_tab_encrypt[] = {
  { "SEQUENCEXYSS", 536875024, NULL },
  { NULL, 1073741836, NULL },
  { "SequenceOfXYSS", 536870917, NULL },
  { "x", 1073741827, NULL },
  { "y", 1073741827, NULL },
  { "sm3", 1073741831, NULL },
  { "secret", 7, NULL },
  { NULL, 0, NULL }
};

const asn1_static_node sequence_asn1_tab_ecg[] = {
  { "SEQUENCEECG", 536875024, NULL },
  { NULL, 1073741836, NULL },
  { "SequenceOfECG", 536870917, NULL },
  { "s1", 1073741831, NULL },
  { "s2", 7, NULL },
  { NULL, 0, NULL }
};

const asn1_static_node sequence_asn1_tab_ecgab[] = {
  { "SEQUENCEECGAB", 536875024, NULL },
  { NULL, 1073741836, NULL },
  { "SequenceOfECGAB", 536870917, NULL },
  { "klen", 1073741827, NULL },
  { "id", 1073741831, NULL },
  { "pk", 1073741858, NULL },
  { "pkr", 34, NULL },
  { NULL, 0, NULL }
};

typedef struct Point {
    mpz_class x;
    mpz_class y; 
    mpz_class z;
} Point;

typedef struct Signdata {
    std::vector<uint8_t> r;
    std::vector<uint8_t> s;
} Signdata;

mpz_class submod(const mpz_class& a, const mpz_class& b, const mpz_class& ecc_p) {
    auto div_ceil = [](const mpz_class& a, const mpz_class& b) -> mpz_class {
        return (a + b - 1) / b;
    };
    if (a > b) {
        return (a - b) % ecc_p;
    } else {
        mpz_class d = b - a;
        mpz_class e = div_ceil(d, ecc_p);
        return e * ecc_p - d;
    }
}

std::vector<uint8_t> kdf(const std::vector<uint8_t>& z, const size_t& klen) {
    std::vector<uint8_t> c;
    uint32_t ct = 0x00000001;
    size_t j = (klen + 31) / 32;
    for (size_t i = 0; i < j; i++) {
        std::vector<uint8_t> tmp;
        tmp.insert(tmp.end(), z.begin(), z.end());
        std::vector<uint8_t> buf;
        std::vector<uint8_t> ct_array = u32_to_byte_array(ct);
        buf.insert(buf.begin(), ct_array.begin(), ct_array.end());
        tmp.insert(tmp.end(), buf.begin(), buf.end());
        std::string hash = sm3_hash(tmp);
        std::vector<uint8_t> hash_byte_array = hex_to_byte_array(hash);
        if (i + 1 == j && klen % 32 != 0) {
            std::vector<uint8_t> hash_byte_array_32(hash_byte_array.begin(), hash_byte_array.begin() + (klen % 32));
            c.insert(c.end(), hash_byte_array_32.begin(), hash_byte_array_32.end());
        } else {
            c.insert(c.end(), hash_byte_array.begin(), hash_byte_array.end());
        }
        ct += 1;
    }
    return c;
}

Point pubkey2point(const std::string& public_key) {
    mpz_class x(public_key.substr(0, PARA_LEN), 16);
    mpz_class y(public_key.substr(PARA_LEN), 16);
    mpz_class z{"1"};
    return Point{x, y, z};
}

Point double_point(const Point& input) {
    mpz_class x1 = input.x;
    mpz_class y1 = input.y;
    mpz_class z1 = input.z;
    mpz_class ecc_p(ECC_P, 16);
    mpz_class t6, t2, t3, t4, t1, t5, z3, x3, y3;
    t6 = (z1 * z1) % ecc_p;
    t2 = (y1 * y1) % ecc_p;
    t3 = (x1 + t6) % ecc_p;
    t4 = submod(x1, t6, ecc_p);
    t1 = (t3 * t4) % ecc_p;
    t3 = (y1 * z1) % ecc_p;
    mpz_class mpz_8("8");
    t4 = (t2 * mpz_8) % ecc_p;
    t5 = (x1 * t4) % ecc_p;
    mpz_class mpz_3("3");
    t1 = (t1 * mpz_3) % ecc_p;
    t6 = (t6 * t6) % ecc_p;
    mpz_class ecc_a(ECC_A, 16);
    mpz_class ecc_a3 = (ecc_a + mpz_3) % ecc_p;
    t6 = (ecc_a3 * t6) % ecc_p;
    t1 = (t1 + t6) % ecc_p;
    z3 = (t3 + t3) % ecc_p;
    t3 = (t1 * t1) % ecc_p;
    t2 = (t2 * t4) % ecc_p;
    x3 = submod(t3, t5, ecc_p);
    mpz_class mpz_2("2");
    mpz_class mpz_1("1");
    if (t5 % mpz_2 == mpz_1) {
        mpz_class tt = t5 + ((t5 + ecc_p) >> 1);
        t4 = submod(tt, t3, ecc_p);
    } else {
        mpz_class tt = t5 + (t5 >> 1);
        t4 = submod(tt, t3, ecc_p);
    }
    t1 = (t1 * t4) % ecc_p;
    y3 = submod(t1, t2, ecc_p);
    return Point{x3, y3, z3};
}

Point add_point(const Point& p1, const Point& p2) {
    mpz_class x1 = p1.x;
    mpz_class y1 = p1.y;
    mpz_class z1 = p1.z;
    mpz_class x2 = p2.x;
    mpz_class y2 = p2.y;
    mpz_class ecc_p(ECC_P, 16);
    mpz_class t1, t2, t3, t4, t5, x3, y3, z3;
    t1 = (z1 * z1) % ecc_p;
    t2 = (y2 * z1) % ecc_p;
    t3 = (x2 * t1) % ecc_p;
    t1 = (t1 * t2) % ecc_p;
    t2 = submod(t3, x1, ecc_p);
    t3 = (t3 + x1) % ecc_p;
    t4 = (t2 * t2) % ecc_p;
    t1 = submod(t1, y1, ecc_p);
    z3 = (z1 * t2) % ecc_p;
    t2 = (t2 * t4) % ecc_p;
    t3 = (t3 * t4) % ecc_p;
    t5 = (t1 * t1) % ecc_p;
    t4 = (x1 * t4) % ecc_p;
    x3 = submod(t5, t3, ecc_p);
    t2 = (y1 * t2) % ecc_p;
    t3 = submod(t4, x3, ecc_p);
    t1 = (t1 * t3) % ecc_p;
    y3 = submod(t1, t2, ecc_p);
    return Point{x3, y3, z3};
}

Point convert_jacb_to_nor(const Point& point) {
    mpz_class ecc_p(ECC_P, 16);
    mpz_class x = point.x;
    mpz_class y = point.y;
    mpz_class z = point.z;
    mpz_class z_1 = z;
    mpz_class mpz_2("2");
    mpz_class z_inv;
    mpz_class temp_1 = ecc_p - mpz_2;
    mpz_powm(z_inv.get_mpz_t(), z.get_mpz_t(), temp_1.get_mpz_t(), ecc_p.get_mpz_t());
    mpz_class z_invsquar = (z_inv * z_inv) % ecc_p;
    mpz_class z_invqube = (z_invsquar * z_inv) % ecc_p;
    mpz_class x_new = (x * z_invsquar) % ecc_p;
    mpz_class y_new = (y * z_invqube) % ecc_p;
    mpz_class z_new = (z_1 * z_inv) % ecc_p;
    mpz_class mpz_1("1");
    mpz_class mpz_0("0");
    if (z_new == mpz_1) {
        return Point{x_new, y_new, z_new};
    } else {
        return Point{mpz_0, mpz_0, mpz_0};
    }
}

Point kg(const mpz_class& p_k, const std::string& p_point_str) {
    mpz_class k = p_k;
    std::string point_str = p_point_str;
    point_str = point_str.append("1");
    mpz_class x(point_str.substr(0, PARA_LEN), 16);
    mpz_class y(point_str.substr(PARA_LEN, PARA_LEN), 16);
    mpz_class z(point_str.substr(PARA_LEN * 2), 16);
    Point point = {x, y, z};
    std::string mask_str = "8";
    for (int i = 0; i < (PARA_LEN - 1); i++) {
        mask_str.append("0");
    }
    mpz_class mask(mask_str, 16);    
    Point temp = point;
    bool flag = false;
    mpz_class mpz_0("0");
    for (int i = 0; i < (PARA_LEN * 4); i++) {
        if (flag) {
            temp = double_point(temp);
        }
        if ((k & mask) != mpz_0) {
            if (flag) {
                temp = add_point(temp, point);
            } else {
                flag = true;
                temp = point;
            }
        }
        k = k << 1;
    }
    Point kg_result = convert_jacb_to_nor(temp);
    return kg_result;
}

std::string gen_sk() {
    std::string d = random_hex(PARA_LEN);
    return d;
}

std::string pk_from_sk(const std::string& private_key) {
    mpz_class mpz_pk(private_key, 16);
    Point p = kg(mpz_pk, ECC_G);
    return format_hex(mpz_to_hex(p.x), mpz_to_hex(p.y));
}

std::string pk_trim(const std::string& public_key) {
    if (public_key.size() == 130 && public_key.substr(0, 2) == "04") {
        return public_key.substr(2);
    } else {
        return public_key;
    }
}

bool pk_valid(const std::string& public_key) {
    std::string public_key_trim = pk_trim(public_key);
    std::string x = public_key_trim.substr(0, 64);
    std::string y = public_key_trim.substr(64, 64);
    mpz_class mpz_x(x, 16);
    mpz_class mpz_y(y, 16);
    mpz_class mpz_a(ECC_A, 16);
    mpz_class mpz_b(ECC_B, 16);
    mpz_class mpz_p(ECC_P, 16);
    mpz_class mpz_n(ECC_N, 16);
    mpz_class mpz_0("0");
    Point point_kg = kg(mpz_n, public_key);
    bool np0 = (point_kg.x == mpz_0 && point_kg.y == mpz_0 && point_kg.z == mpz_0);
    bool on_curve = ((mpz_y * mpz_y) % mpz_p == (mpz_x * mpz_x * mpz_x + mpz_a * mpz_x + mpz_b) % mpz_p);
    return np0 && on_curve;
}

std::vector<uint8_t> sk_to_sk_pem_bytes(const std::string& private_key) {
    std::string public_key = pk_from_sk(private_key);
    std::string pem = "308187020100301306072a8648ce3d020106082a811ccf5501822d046d306b0201010420" + private_key + "a14403420004" + public_key;
    std::vector<uint8_t> pem_bytes = hex_to_byte_array(pem);
    std::string pem_base64 = enc_base64(pem_bytes);
    std::string pem_pkcs8 = "-----BEGIN PRIVATE KEY-----";
    pem_pkcs8.append("\n");
    pem_pkcs8 += pem_base64.substr(0, 64);
    pem_pkcs8.append("\n");
    pem_pkcs8 += pem_base64.substr(64, 64);
    pem_pkcs8.append("\n");
    pem_pkcs8 += pem_base64.substr(128);
    pem_pkcs8.append("\n");
    pem_pkcs8 += "-----END PRIVATE KEY-----";
    pem_pkcs8.append("\n");
    std::vector<uint8_t> pem_file_bytes(pem_pkcs8.begin(), pem_pkcs8.end());
    return pem_file_bytes;
}

std::string sk_from_sk_pem_bytes(const std::vector<uint8_t>& pem_bytes) {
    std::vector<uint8_t> base64_byte_array;
    std::vector<uint8_t> part_1(pem_bytes.begin() + 28, pem_bytes.begin() + 28 + 64);
    std::vector<uint8_t> part_2(pem_bytes.begin() + 93, pem_bytes.begin() + 93 + 64);
    std::vector<uint8_t> part_3(pem_bytes.begin() + 158, pem_bytes.begin() + 158 + 56);
    base64_byte_array = concvec(part_1, part_2);
    base64_byte_array = concvec(base64_byte_array, part_3);
    std::string base64_string(base64_byte_array.begin(), base64_byte_array.end());
    std::vector<uint8_t> byte_array = dec_base64(base64_string);
    std::string byte_array_hex = byte_array_to_hex(byte_array);
    return byte_array_hex.substr(72, 64);
}

std::string pk_from_sk_pem_bytes(const std::vector<uint8_t>& pem_bytes) {
    std::vector<uint8_t> base64_byte_array;
    std::vector<uint8_t> part_1(pem_bytes.begin() + 28, pem_bytes.begin() + 28 + 64);
    std::vector<uint8_t> part_2(pem_bytes.begin() + 93, pem_bytes.begin() + 93 + 64);
    std::vector<uint8_t> part_3(pem_bytes.begin() + 158, pem_bytes.begin() + 158 + 56);
    base64_byte_array = concvec(part_1, part_2);
    base64_byte_array = concvec(base64_byte_array, part_3);
    std::string base64_string(base64_byte_array.begin(), base64_byte_array.end());
    std::vector<uint8_t> byte_array = dec_base64(base64_string);
    std::string byte_array_hex = byte_array_to_hex(byte_array);
    return byte_array_hex.substr(72 + 64 + 12, 128);
}

std::vector<uint8_t> pk_to_pk_pem_bytes(const std::string& public_key) {
    std::string public_key_trim = pk_trim(public_key);
    std::string pem = "3059301306072a8648ce3d020106082a811ccf5501822d03420004" + public_key_trim;
    std::vector<uint8_t> pem_bytes = hex_to_byte_array(pem);
    std::string pem_base64 = enc_base64(pem_bytes);
    std::string pem_pkcs8 = "-----BEGIN PUBLIC KEY-----";
    pem_pkcs8.append("\n");
    pem_pkcs8 += pem_base64.substr(0, 64);
    pem_pkcs8.append("\n");
    pem_pkcs8 += pem_base64.substr(64);
    pem_pkcs8.append("\n");
    pem_pkcs8 += "-----END PUBLIC KEY-----";
    pem_pkcs8.append("\n");
    std::vector<uint8_t> pem_file_bytes(pem_pkcs8.begin(), pem_pkcs8.end());
    return pem_file_bytes;
}

std::string pk_from_pk_pem_bytes(const std::vector<uint8_t>& pem_bytes) {
    std::vector<uint8_t> base64_byte_array;
    std::vector<uint8_t> part_1(pem_bytes.begin() + 27, pem_bytes.begin() + 27 + 64);
    std::vector<uint8_t> part_2(pem_bytes.begin() + 92, pem_bytes.begin() + 92 + 60);
    base64_byte_array = concvec(part_1, part_2);
    std::string base64_string(base64_byte_array.begin(), base64_byte_array.end());
    std::vector<uint8_t> byte_array = dec_base64(base64_string);
    std::string byte_array_hex = byte_array_to_hex(byte_array);
    return byte_array_hex.substr(54);
}

std::vector<uint8_t> asn1_construct_rs(const Signdata& signdata) {
    asn1_node definations = NULL, node = NULL;
    asn1_array2tree(sequence_asn1_tab_sign, &definations, nullptr);
    asn1_create_element(definations, "SEQUENCERS.SequenceOfRS", &node);
    std::vector<uint8_t> r_byte = signdata.r;
    std::vector<uint8_t> s_byte = signdata.s;
    r_byte = pad_zero_positive(r_byte);
    s_byte = pad_zero_positive(s_byte);
    asn1_write_value(node, "r", r_byte.data(), r_byte.size());
    asn1_write_value(node, "s", s_byte.data(), s_byte.size());
    char buffer[1024];
    int buffer_size = sizeof(buffer);
    asn1_der_coding(node, "", buffer, &buffer_size, nullptr);
    asn1_delete_structure(&node);
    asn1_delete_structure(&definations);
    std::vector<uint8_t> result(buffer, buffer + buffer_size / sizeof(char));
    return result;
}

Signdata asn1_parse_rs(const std::vector<uint8_t>& asn1_rs_data) {
    asn1_node definations = NULL, node = NULL;
    asn1_array2tree(sequence_asn1_tab_sign, &definations, nullptr);
    asn1_create_element(definations, "SEQUENCERS.SequenceOfRS", &node);
    asn1_der_decoding(&node, asn1_rs_data.data(), asn1_rs_data.size() * sizeof(char), nullptr);
    char r_value[1024], s_value[1024];
    int r_len = sizeof(r_value);
    int s_len = sizeof(s_value);
    asn1_read_value(node, "r", r_value, &r_len);
    asn1_read_value(node, "s", s_value, &s_len);
    asn1_delete_structure(&node);
    asn1_delete_structure(&definations);
    std::vector<uint8_t> r_value_vec(r_value, r_value + r_len / sizeof(char));
    std::vector<uint8_t> s_value_vec(s_value, s_value + s_len / sizeof(char));
    r_value_vec = appendzero(r_value_vec, 32);
    r_value_vec = removezero(r_value_vec, 32);
    s_value_vec = appendzero(s_value_vec, 32);
    s_value_vec = removezero(s_value_vec, 32);
    return Signdata {r_value_vec, s_value_vec};
}

std::vector<uint8_t> sign_raw(const std::vector<uint8_t>& data, const std::string& private_key) {
    mpz_class e(byte_array_to_hex(data), 16);    
    mpz_class d(private_key, 16);
    std::string k_hex = random_hex(PARA_LEN);
    mpz_class k(k_hex, 16);
    mpz_class k1 = k;
    Point p1 = kg(k, ECC_G);
    mpz_class mpz_ecc_n(ECC_N, 16);
    mpz_class r = (e + p1.x) % mpz_ecc_n;
    mpz_class mpz_1("1");
    mpz_class mpz_2("2");
    mpz_class d_1;
    mpz_class base_1 = d + mpz_1;
    mpz_class exp_1 = mpz_ecc_n - mpz_2;
    mpz_class mod_1 = mpz_ecc_n;
    mpz_powm(d_1.get_mpz_t(), base_1.get_mpz_t(), exp_1.get_mpz_t(), mod_1.get_mpz_t());
    mpz_class s = (d_1 * (k1 + r) - r) % mpz_ecc_n;
    Signdata sign_data = Signdata{mpz_to_byte_array(r), mpz_to_byte_array(s)};
    return asn1_construct_rs(sign_data);
}

bool verify_raw(const std::vector<uint8_t>& data, const std::vector<uint8_t>& sign, const std::string& public_key) {
    Signdata sign_data = asn1_parse_rs(sign);
    mpz_class r = byte_array_to_mpz(sign_data.r);
    mpz_class s = byte_array_to_mpz(sign_data.s);    
    mpz_class e(byte_array_to_hex(data), 16);    
    mpz_class ecc_n(ECC_N, 16);
    mpz_class t = (r + s) % ecc_n;
    mpz_class mpz_0("0");
    bool result;
    if (t == mpz_0) {
        result = false;
    } else {
        Point p1 = kg(s, ECC_G);
        Point p2 = kg(t, public_key);
        if (p1.x == p2.x && p1.y == p2.y && p1.z == p2.z) {
            p1 = double_point(p1);
        } else {
            p1 = add_point(p1, p2);
            p1 = convert_jacb_to_nor(p1);
        }
        mpz_class x = p1.x;
        result = (r == (e + x) % ecc_n);
    }
    return result;
}

std::string zab(const std::string& public_key, const std::vector<uint8_t>& uid) {
    size_t entla = 8 * uid.size();
    std::vector<uint8_t> za_1 = {(uint8_t)((entla >> 8) & 0xFF), (uint8_t)(entla & 0xFF)};
    std::vector<uint8_t> za = concvec(za_1, uid);
    za = concvec(za, hex_to_byte_array(ECC_A));
    za = concvec(za, hex_to_byte_array(ECC_B));
    za = concvec(za, hex_to_byte_array(ECC_G));
    za = concvec(za, hex_to_byte_array(public_key));
    return sm3_hash(za);
}

std::vector<uint8_t> sign_byte(const std::vector<uint8_t>& id, const std::vector<uint8_t>& data, const std::string& private_key) {
    std::string public_key = pk_from_sk(private_key);
    std::vector<uint8_t> m_bar = concvec(hex_to_byte_array(zab(public_key, id)), data);
    std::vector<uint8_t> e = hex_to_byte_array(sm3_hash(m_bar));
    return sign_raw(e, private_key);
}

bool verify_byte(const std::vector<uint8_t>& id, const std::vector<uint8_t>& data, const std::vector<uint8_t>& sign, const std::string& public_key) {
    std::vector<uint8_t> m_bar = concvec(hex_to_byte_array(zab(public_key, id)), data);
    std::vector<uint8_t> e = hex_to_byte_array(sm3_hash(m_bar));
    return verify_raw(e, sign, public_key);
}

std::string sign_string(const std::string& id, const std::string& data, const std::string& private_key) {
    std::vector<uint8_t> id_bytes(id.begin(), id.end());
    std::vector<uint8_t> data_bytes(data.begin(), data.end());
    std::vector<uint8_t> sign_bytes = sign_byte(id_bytes, data_bytes, private_key);
    return enc_base64(sign_bytes);
}

bool verify_string(const std::string& id, const std::string& data, const std::string& sign_base64, const std::string& public_key) {
    std::vector<uint8_t> id_bytes(id.begin(), id.end());
    std::vector<uint8_t> data_bytes(data.begin(), data.end());
    std::vector<uint8_t> sign_bytes = dec_base64(sign_base64);
    return verify_byte(id_bytes, data_bytes, sign_bytes, public_key);
}

std::vector<uint8_t> encrypt_raw(const std::vector<uint8_t>& data, const std::string& public_key) {
    std::string k_hex = random_hex(PARA_LEN);
    mpz_class k_mpz(k_hex, 16);
    Point c1xyz = kg(k_mpz, ECC_G);
    std::vector<uint8_t> c1x = appendzero(mpz_to_byte_array(c1xyz.x), PARA_LEN / 2);
    std::vector<uint8_t> c1y = appendzero(mpz_to_byte_array(c1xyz.y), PARA_LEN / 2);
    std::vector<uint8_t> c1 = concvec(c1x, c1y);
    Point xy = kg(k_mpz, public_key);
    std::vector<uint8_t> x2 = mpz_to_byte_array(xy.x);
    std::vector<uint8_t> y2 = mpz_to_byte_array(xy.y);
    x2 = appendzero(x2, PARA_LEN / 2);
    y2 = appendzero(y2, PARA_LEN / 2);
    std::vector<uint8_t> xyv = concvec(x2, y2);
    std::vector<uint8_t> t = kdf(xyv, data.size());
    mpz_class c2_mpz = byte_array_to_mpz(data) ^ byte_array_to_mpz(t);
    std::vector<uint8_t> c2 = mpz_to_byte_array(c2_mpz);
    c2 = appendzero(c2, data.size());
    std::vector<uint8_t> h = concvec(concvec(x2, data), y2);
    std::vector<uint8_t> c3 = hex_to_byte_array(sm3_hash(h));
    std::vector<uint8_t> cipher = concvec(concvec(c1, c3), c2);
    return cipher;
}

std::vector<uint8_t> decrypt_raw(const std::vector<uint8_t>& cipher, const std::string& private_key) {
    std::vector<uint8_t> c1(cipher.begin(), cipher.begin() + 64);
    std::vector<uint8_t> c2(cipher.begin() + 96, cipher.end());
    mpz_class mpz_sk(private_key, 16);
    Point xy = kg(mpz_sk, byte_array_to_hex(c1));
    std::vector<uint8_t> x = appendzero(mpz_to_byte_array(xy.x), 32);
    std::vector<uint8_t> y = appendzero(mpz_to_byte_array(xy.y), 32);
    std::vector<uint8_t> xyv = concvec(x, y);
    std::vector<uint8_t> t = kdf(xyv, c2.size());
    std::vector<uint8_t> result = mpz_to_byte_array(byte_array_to_mpz(c2) ^ byte_array_to_mpz(t));
    return result;
}

std::vector<uint8_t> encrypt_byte(const std::vector<uint8_t>& data, const std::string& public_key) {
    std::vector<uint8_t> cipher = encrypt_raw(data, public_key);
    std::vector<uint8_t> x(cipher.begin(), cipher.begin() + 32);
    std::vector<uint8_t> y(cipher.begin() + 32, cipher.begin() + 64);
    std::vector<uint8_t> sm3(cipher.begin() + 64, cipher.begin() + 96);
    std::vector<uint8_t> secret(cipher.begin() + 96, cipher.end());
    asn1_node definations = NULL, node = NULL;
    asn1_array2tree(sequence_asn1_tab_encrypt, &definations, nullptr);
    asn1_create_element(definations, "SEQUENCEXYSS.SequenceOfXYSS", &node);
    x = pad_zero_positive(x);
    y = pad_zero_positive(y);
    asn1_write_value(node, "x", x.data(), x.size());
    asn1_write_value(node, "y", y.data(), y.size());
    asn1_write_value(node, "sm3", sm3.data(), sm3.size());
    asn1_write_value(node, "secret", secret.data(), secret.size());
    char buffer[1024];
    int buffer_size = sizeof(buffer);
    asn1_der_coding(node, "", buffer, &buffer_size, nullptr);
    asn1_delete_structure(&node);
    asn1_delete_structure(&definations);
    std::vector<uint8_t> result(buffer, buffer + buffer_size / sizeof(char));
    return result;
}

std::vector<uint8_t> decrypt_byte(const std::vector<uint8_t>& asn1_encrypt_data, const std::string& private_key) {
    asn1_node definations = NULL, node = NULL;
    asn1_array2tree(sequence_asn1_tab_encrypt, &definations, nullptr);
    asn1_create_element(definations, "SEQUENCEXYSS.SequenceOfXYSS", &node);
    asn1_der_decoding(&node, asn1_encrypt_data.data(), asn1_encrypt_data.size() * sizeof(char), nullptr);
    char x_value[1024], y_value[1024], sm3_value[1024], secret_value[1024];
    int x_len = sizeof(x_value);
    int y_len = sizeof(y_value);
    int sm3_len = sizeof(sm3_value);
    int secret_len = sizeof(secret_value);
    asn1_read_value(node, "x", x_value, &x_len);
    asn1_read_value(node, "y", y_value, &y_len);
    asn1_read_value(node, "sm3", sm3_value, &sm3_len);
    asn1_read_value(node, "secret", secret_value, &secret_len);
    asn1_delete_structure(&node);
    asn1_delete_structure(&definations);
    std::vector<uint8_t> x_vec(x_value, x_value + x_len / sizeof(char));
    std::vector<uint8_t> y_vec(y_value, y_value + y_len / sizeof(char));
    std::vector<uint8_t> sm3_vec(sm3_value, sm3_value + sm3_len / sizeof(char));
    std::vector<uint8_t> secret_vec(secret_value, secret_value + secret_len / sizeof(char));
    x_vec = appendzero(x_vec, 32);
    x_vec = removezero(x_vec, 32);
    y_vec = appendzero(y_vec, 32);
    y_vec = removezero(y_vec, 32);
    std::vector<uint8_t> cipher = concvec(concvec(concvec(x_vec, y_vec), sm3_vec), secret_vec);
    return decrypt_raw(cipher, private_key);
}

std::string encrypt_string(const std::string& data_string, const std::string& public_key) {
    std::vector<uint8_t> data_bytes(data_string.begin(), data_string.end());
    std::vector<uint8_t> result_encrypt_bytes = encrypt_byte(data_bytes, public_key);
    return enc_base64(result_encrypt_bytes);
}

std::string decrypt_string(const std::string& asn1_encrypt_data_base64, const std::string& private_key) {
    std::vector<uint8_t> asn1_encrypt_data_bytes = dec_base64(asn1_encrypt_data_base64);
    std::vector<uint8_t> decrypt_bytes = decrypt_byte(asn1_encrypt_data_bytes, private_key);
    std::string result_decrypt_string(decrypt_bytes.begin(), decrypt_bytes.end());
    return result_decrypt_string;
}

mpz_class kexhat(const mpz_class& x) {
    std::vector<uint8_t> w_2_b = {0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    mpz_class w_2 = byte_array_to_mpz(w_2_b);
    mpz_class mpz_1("1");
    return w_2 + (x & (w_2 - mpz_1));
}

std::pair<std::string, std::string> keyexchange_raw(const size_t& klen, const std::vector<uint8_t>& ida, const std::vector<uint8_t>& idb, const std::string& private_key, const std::string& public_key, const std::string& r_private_key, const std::string& r_public_key, const bool& is_a) {
    mpz_class mpz_rsk_64(pk_from_sk(r_private_key).substr(0, 64), 16);
    mpz_class mpz_rsk_64_end(pk_from_sk(r_private_key).substr(64), 16);
    mpz_class x2hat = kexhat(mpz_rsk_64);
    mpz_class mpz_rsk(r_private_key, 16);
    mpz_class x2rb = x2hat * mpz_rsk;
    mpz_class mpz_sk(private_key, 16);
    mpz_class tbt = mpz_sk + x2rb;
    mpz_class mpz_ecc_n(ECC_N, 16);
    mpz_class tb = tbt % mpz_ecc_n;
    mpz_class mpz_rpk_64(r_public_key.substr(0, 64), 16);
    mpz_class mpz_rpk_64_end(r_public_key.substr(64), 16);
    mpz_class x1hat = kexhat(mpz_rpk_64);
    Point kx1y1 = kg(x1hat, r_public_key);
    Point vxyt_p = convert_jacb_to_nor(add_point(pubkey2point(public_key), kx1y1));
    std::string vxyt = format_hex(mpz_to_hex(vxyt_p.x), mpz_to_hex(vxyt_p.y));
    Point vxy = kg(tb, vxyt);
    mpz_class vx = vxy.x;
    mpz_class vy = vxy.y;
    std::string pza;
    if (is_a) {
        pza = pk_from_sk(private_key);
    } else {
        pza = public_key;
    }
    std::string za = zab(pza, ida);
    std::string pzb;
    if (!is_a) {
        pzb = pk_from_sk(private_key);
    } else {
        pzb = public_key;
    }
    std::string zb = zab(pzb, idb);
    std::vector<uint8_t> z_byte;
    z_byte = concvec(mpz_to_byte_array(vx), mpz_to_byte_array(vy));
    z_byte = concvec(z_byte, hex_to_byte_array(za));
    z_byte = concvec(z_byte, hex_to_byte_array(zb));
    std::string z_hex = byte_array_to_hex(z_byte);
    std::vector<uint8_t> z(z_hex.begin(), z_hex.end());
    std::vector<uint8_t> h1;
    std::vector<uint8_t> h1_1 = mpz_to_byte_array(vx);
    std::vector<uint8_t> h1_2(za.begin(), za.end());
    std::vector<uint8_t> h1_3(zb.begin(), zb.end());
    std::vector<uint8_t> h1_4 = mpz_to_byte_array(mpz_rsk_64);
    std::vector<uint8_t> h1_5 = mpz_to_byte_array(mpz_rsk_64_end);
    std::vector<uint8_t> h1_6 = mpz_to_byte_array(mpz_rpk_64);
    std::vector<uint8_t> h1_7 = mpz_to_byte_array(mpz_rpk_64_end);
    if (!is_a) {
        h1 = concvec(h1_1, h1_2);
        h1 = concvec(h1, h1_3);
        h1 = concvec(h1, h1_4);
        h1 = concvec(h1, h1_5);
        h1 = concvec(h1, h1_6);
        h1 = concvec(h1, h1_7);
    } else {
        h1 = concvec(h1_1, h1_2);
        h1 = concvec(h1, h1_3);
        h1 = concvec(h1, h1_6);
        h1 = concvec(h1, h1_7);
        h1 = concvec(h1, h1_4);
        h1 = concvec(h1, h1_5);
    }
    std::string hash = sm3_hash(h1);
    std::vector<uint8_t> h2 = concvec(hex_to_byte_array("02"), mpz_to_byte_array(vy));
    h2 = concvec(h2, hex_to_byte_array(hash));
    std::string s1 = sm3_hash(h2);
    std::vector<uint8_t> h3 = concvec(hex_to_byte_array("03"), mpz_to_byte_array(vy));
    h3 = concvec(h3, hex_to_byte_array(hash));
    std::string s2 = sm3_hash(h3);
    asn1_node definations = NULL, node = NULL;
    asn1_array2tree(sequence_asn1_tab_ecg, &definations, nullptr);
    asn1_create_element(definations, "SEQUENCEECG.SequenceOfECG", &node);
    asn1_write_value(node, "s1", s1.data(), s1.size());
    asn1_write_value(node, "s2", s2.data(), s2.size());
    char buffer[1024];
    int buffer_size = sizeof(buffer);
    asn1_der_coding(node, "", buffer, &buffer_size, nullptr);
    asn1_delete_structure(&node);
    asn1_delete_structure(&definations);
    std::vector<uint8_t> s12(buffer, buffer + buffer_size / sizeof(char));
    std::string k_hex = byte_array_to_hex(kdf(z, klen));
    std::string s12_hex = byte_array_to_hex(s12);
    return {k_hex, s12_hex};
}

std::pair<std::string, std::string> keyexchange_a(const size_t& klen, const std::vector<uint8_t>& ida, const std::vector<uint8_t>& idb, const std::string& private_key_a, const std::string& public_key_b, const std::string& private_key_ar, const std::string& public_key_br) {
    return keyexchange_raw(klen, ida, idb, private_key_a, public_key_b, private_key_ar, public_key_br, true);
}

std::pair<std::string, std::string> keyexchange_b(const size_t& klen, const std::vector<uint8_t>& idb, const std::vector<uint8_t>& ida, const std::string& private_key_b, const std::string& public_key_a, const std::string& private_key_br, const std::string& public_key_ar) {
    return keyexchange_raw(klen, ida, idb, private_key_b, public_key_a, private_key_br, public_key_ar, false);
}

std::pair<std::string, std::string> keyexchange_1ab(const size_t& klen, const std::string& id, const std::string& private_key) {
    std::vector<uint8_t> id_bytes(id.begin(), id.end());
    std::string public_key = pk_from_sk(private_key);
    std::string private_key_r = gen_sk();
    std::string public_key_r = pk_from_sk(private_key_r);
    std::vector<uint8_t> klen_bytes = u32_to_byte_array(static_cast<uint32_t>(klen));
    klen_bytes = pad_zero_positive(klen_bytes);
    asn1_node definations = NULL, node = NULL;
    asn1_array2tree(sequence_asn1_tab_ecgab, &definations, nullptr);
    asn1_create_element(definations, "SEQUENCEECGAB.SequenceOfECGAB", &node);
    asn1_write_value(node, "klen", klen_bytes.data(), klen_bytes.size());
    asn1_write_value(node, "id", id_bytes.data(), id_bytes.size());
    asn1_write_value(node, "pk", public_key.c_str(), public_key.size());
    asn1_write_value(node, "pkr", public_key_r.c_str(), public_key_r.size());
    std::vector<uint8_t> result;
    int len = 0;
    asn1_der_coding(node, "", NULL, &len, NULL);
    result.resize(len);
    asn1_der_coding(node, "", result.data(), &len, NULL);
    asn1_delete_structure(&node);
    asn1_delete_structure(&definations);
    std::string result_base64 = enc_base64(result);
    return {result_base64, private_key_r};
}

std::pair<std::string, std::string> keyexchange_2a(const std::string& id, const std::string& private_key, const std::string& private_key_r, const std::string& recive_from_b) {
    std::vector<uint8_t> id_bytes(id.begin(), id.end());
    std::vector<uint8_t> recive_bytes = dec_base64(recive_from_b);
    asn1_node definations = NULL, node = NULL;
    asn1_array2tree(sequence_asn1_tab_ecgab, &definations, nullptr);
    asn1_create_element(definations, "SEQUENCEECGAB.SequenceOfECGAB", &node);
    asn1_der_decoding(&node, recive_bytes.data(), recive_bytes.size() * sizeof(char), nullptr);
    char klen_value[1024], id_value[1024], pk_value[1024], pkr_value[1024];
    int klen_len = sizeof(klen_value);
    int id_len = sizeof(id_value);
    int pk_len = sizeof(pk_value);
    int pkr_len = sizeof(pkr_value);
    asn1_read_value(node, "klen", klen_value, &klen_len);
    asn1_read_value(node, "id", id_value, &id_len);
    asn1_read_value(node, "pk", pk_value, &pk_len);
    asn1_read_value(node, "pkr", pkr_value, &pkr_len);
    asn1_delete_structure(&node);
    asn1_delete_structure(&definations);
    std::vector<uint8_t> klen_vec(klen_value, klen_value + klen_len / sizeof(char));
    std::vector<uint8_t> id_vec(id_value, id_value + id_len / sizeof(char));
    std::vector<uint8_t> pk_vec(pk_value, pk_value + pk_len / sizeof(char));
    std::vector<uint8_t> pkr_vec(pkr_value, pkr_value + pkr_len / sizeof(char));
    klen_vec = appendzero(klen_vec, 4);
    klen_vec = removezero(klen_vec, 4);
    size_t klen = byte_array_to_u32(klen_vec);
    std::string pk(pk_vec.begin(), pk_vec.end());
    std::string pkr(pkr_vec.begin(), pkr_vec.end());
    return keyexchange_a(klen, id_bytes, id_vec, private_key, pk, private_key_r, pkr);
}

std::pair<std::string, std::string> keyexchange_2b(const std::string& id, const std::string& private_key, const std::string& private_key_r, const std::string& recive_from_a) {
    std::vector<uint8_t> id_bytes(id.begin(), id.end());
    std::vector<uint8_t> recive_bytes = dec_base64(recive_from_a);
    asn1_node definations = NULL, node = NULL;
    asn1_array2tree(sequence_asn1_tab_ecgab, &definations, nullptr);
    asn1_create_element(definations, "SEQUENCEECGAB.SequenceOfECGAB", &node);
    asn1_der_decoding(&node, recive_bytes.data(), recive_bytes.size() * sizeof(char), nullptr);
    char klen_value[1024], id_value[1024], pk_value[1024], pkr_value[1024];
    int klen_len = sizeof(klen_value);
    int id_len = sizeof(id_value);
    int pk_len = sizeof(pk_value);
    int pkr_len = sizeof(pkr_value);
    asn1_read_value(node, "klen", klen_value, &klen_len);
    asn1_read_value(node, "id", id_value, &id_len);
    asn1_read_value(node, "pk", pk_value, &pk_len);
    asn1_read_value(node, "pkr", pkr_value, &pkr_len);
    asn1_delete_structure(&node);
    asn1_delete_structure(&definations);
    std::vector<uint8_t> klen_vec(klen_value, klen_value + klen_len / sizeof(char));
    std::vector<uint8_t> id_vec(id_value, id_value + id_len / sizeof(char));
    std::vector<uint8_t> pk_vec(pk_value, pk_value + pk_len / sizeof(char));
    std::vector<uint8_t> pkr_vec(pkr_value, pkr_value + pkr_len / sizeof(char));
    klen_vec = appendzero(klen_vec, 4);
    klen_vec = removezero(klen_vec, 4);
    size_t klen = byte_array_to_u32(klen_vec);
    std::string pk(pk_vec.begin(), pk_vec.end());
    std::string pkr(pkr_vec.begin(), pkr_vec.end());
    return keyexchange_b(klen, id_bytes, id_vec, private_key, pk, private_key_r, pkr);
}




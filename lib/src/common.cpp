// relative includes
#include "common.h"

// C++ includes
#include <cstring>
#include <iomanip>
#include <sstream>

// other
#include <openssl/evp.h>

using byte_t = unsigned char;

static const std::string BASE64_CHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
                                        "abcdefghijklmnopqrstuvwxyz"
                                        "0123456789+/";

//! Check if char element is base64
static bool __is_base64(byte_t c);

//! Get cipher name from enum value
std::string get_cipher_name(Cipher cipher) {
    std::string ciph = "";
    if (cipher == Cipher::AES_128_CBC) {
        ciph = "aes-128-cbc";
    } else if (cipher == Cipher::AES_256_CBC) {
        ciph = "aes-256-cbc";
    }
    return ciph;
}

//! Extract key and iv from password due to salt
std::pair<std::vector<byte_t>, std::vector<byte_t>> get_key_iv_from_pass(const byte_t*      salt,
                                                                         const int          salt_sz,
                                                                         const std::string& pass,
                                                                         Cipher             cipher,
                                                                         Digest digest) {
    // 1.Use cipher
    const std::string cipher_name = get_cipher_name(cipher);

    const EVP_CIPHER* evp_cipher = EVP_get_cipherbyname(cipher_name.c_str());
    int               ik_len     = EVP_CIPHER_key_length(evp_cipher);
    int               iv_len     = EVP_CIPHER_iv_length(evp_cipher);

    // 2.Use digest
    std::string dgst = "";
    if (digest == Digest::SHA256) {
        dgst = "sha256";
    }

    const EVP_MD* evp_dgst = EVP_get_digestbyname(dgst.c_str());

    // 3.Use password-based key derivation function 2 and 1000 as iter count
    const int iter_cnt = 1000;
    byte_t    pair_key_iv[EVP_MAX_KEY_LENGTH + EVP_MAX_IV_LENGTH];
    if (PKCS5_PBKDF2_HMAC(pass.c_str(),
                          pass.length(),
                          salt,
                          salt_sz,
                          iter_cnt,
                          evp_dgst,
                          ik_len + iv_len,
                          pair_key_iv) != 1) {
        return {};
    }

    // 4.Extract from pair key/iv
    std::vector<byte_t> key(ik_len);
    memcpy(key.data(), pair_key_iv, ik_len);

    std::vector<byte_t> iv(iv_len);
    memcpy(iv.data(), pair_key_iv + ik_len, iv_len);

    return {key, iv};
}

//! Get raw bytes from string base64 format
std::vector<byte_t> str_base64_to_bytes(const std::string& encoded_str_base64) {
    std::vector<unsigned char> out;

    unsigned char char_array_4[4];
    unsigned char char_array_3[3];

    int i = 0;
    int j = 0;

    std::string ret;

    int idxlen = encoded_str_base64.size();
    int idx    = 0;

    while (idxlen-- && (encoded_str_base64[idx] != '=') && __is_base64(encoded_str_base64[idx])) {
        char_array_4[i++] = encoded_str_base64[idx];
        idx++;
        if (i == 4) {
            for (i = 0; i < 4; i++)
                char_array_4[i] = BASE64_CHARS.find(char_array_4[i]);

            char_array_3[0] = (char_array_4[0] << 2) + ((char_array_4[1] & 0x30) >> 4);
            char_array_3[1] = ((char_array_4[1] & 0xf) << 4) + ((char_array_4[2] & 0x3c) >> 2);
            char_array_3[2] = ((char_array_4[2] & 0x3) << 6) + char_array_4[3];

            for (i = 0; (i < 3); i++) {
                out.push_back(char_array_3[i]);
            }
            i = 0;
        }
    }

    if (i) {
        for (j = i; j < 4; j++)
            char_array_4[j] = 0;

        for (j = 0; j < 4; j++)
            char_array_4[j] = BASE64_CHARS.find(char_array_4[j]);

        char_array_3[0] = (char_array_4[0] << 2) + ((char_array_4[1] & 0x30) >> 4);
        char_array_3[1] = ((char_array_4[1] & 0xf) << 4) + ((char_array_4[2] & 0x3c) >> 2);
        char_array_3[2] = ((char_array_4[2] & 0x3) << 6) + char_array_4[3];

        for (j = 0; (j < i - 1); j++) {
            out.push_back(char_array_3[j]);
        }
    }

    return out;
}

//! Get string in base64 format from raw bytes
std::string bytes_to_str_base64(const std::vector<unsigned char>& bytes) {
    std::string base64_str;

    byte_t char_array_4[4];
    byte_t char_array_3[3];

    int i = 0;
    int j = 0;

    int           in_len          = bytes.size();
    const byte_t* bytes_to_encode = bytes.data();

    while (in_len--) {
        char_array_3[i++] = *(bytes_to_encode++);
        if (i == 3) {
            char_array_4[0] = (char_array_3[0] & 0xfc) >> 2;
            char_array_4[1] = ((char_array_3[0] & 0x03) << 4) + ((char_array_3[1] & 0xf0) >> 4);
            char_array_4[2] = ((char_array_3[1] & 0x0f) << 2) + ((char_array_3[2] & 0xc0) >> 6);
            char_array_4[3] = char_array_3[2] & 0x3f;

            for (i = 0; (i < 4); i++) {
                base64_str += BASE64_CHARS[char_array_4[i]];
            }
            i = 0;
        }
    }

    if (i) {
        for (j = i; j < 3; j++)
            char_array_3[j] = '\0';

        char_array_4[0] = (char_array_3[0] & 0xfc) >> 2;
        char_array_4[1] = ((char_array_3[0] & 0x03) << 4) + ((char_array_3[1] & 0xf0) >> 4);
        char_array_4[2] = ((char_array_3[1] & 0x0f) << 2) + ((char_array_3[2] & 0xc0) >> 6);
        char_array_4[3] = char_array_3[2] & 0x3f;

        for (j = 0; (j < i + 1); j++) {
            base64_str += BASE64_CHARS[char_array_4[j]];
        }

        while ((i++ < 3)) {
            base64_str += '=';
        }
    }

    return base64_str;
}

bool __is_base64(byte_t c) {
    return (isalnum(c) || (c == '+') || (c == '/'));
}

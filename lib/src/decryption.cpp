// lib includes
#include <aes_demo/decryption.h>

// relative includes
#include "common.h"

// C++ includes
#include <cstring>

// GNU C library includes
#include <openssl/evp.h>

using byte_t = unsigned char;

//! Decrypt
static std::pair<bool, std::vector<byte_t>> __decrypt(const std::vector<byte_t>& cipher_text_bytes,
                                                      const std::vector<byte_t>& key_bytes,
                                                      const std::vector<byte_t>& iv_bytes,
                                                      Cipher                     cipher);

//! Decrypt string message
std::pair<bool, std::string> aes_with_salt_decrypt(const std::string& input_base64,
                                                   Cipher             cipher,
                                                   Digest             digest,
                                                   const std::string& password) {
    // 1.Convert base64 encrypted string to raw bytes
    std::vector<byte_t> encrypted_raw = str_base64_to_bytes(input_base64);

    // 2.Get salt from encrypted message (it is keeping in the message header)
    const int salt_sz = 8; // 8 first bytes (should ignore prefix "Salted__")
    byte_t    salt[salt_sz];
    memcpy(salt, encrypted_raw.data() + 8, salt_sz);

    // 3.Get key and iv from password due to salt
    std::pair<std::vector<byte_t>, std::vector<byte_t>> key_iv =
        get_key_iv_from_pass(salt, salt_sz, password, cipher, digest);

    const std::vector<byte_t>& key = key_iv.first;
    const std::vector<byte_t>& iv  = key_iv.second;

    // 4.Decrypt due to salt, key and IV

    // 4.1.First 16 bytes is extra (8 - magic value, 8 - salt)
    int                 encrypted_data_sz = encrypted_raw.size() - 16;
    std::vector<byte_t> encrypted_data(encrypted_data_sz);
    memcpy(encrypted_data.data(), encrypted_raw.data() + 16, encrypted_data_sz);

    // 4.2.Decrypt
    std::pair<bool, std::vector<byte_t>> decryption = __decrypt(encrypted_data, key, iv, cipher);
    if (!decryption.first) {
        return {false, ""};
    }

    // 5.Convert to string
    const std::vector<byte_t>& decrypted_bytes = decryption.second;

    std::string output(reinterpret_cast<const char*>(decrypted_bytes.data()),
                       decrypted_bytes.size());

    return {true, output};
}

std::pair<bool, std::vector<byte_t>> __decrypt(const std::vector<byte_t>& cipher_text_bytes,
                                               const std::vector<byte_t>& key_bytes,
                                               const std::vector<byte_t>& iv_bytes,
                                               Cipher                     cipher) {
    // 1.Create and initialize the context
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (ctx == nullptr) {
        return {false, {}};
    }

    // 2.Initialize the decryption operation
    const std::string cipher_name = get_cipher_name(cipher);
    const EVP_CIPHER* evp_cipher  = EVP_get_cipherbyname(cipher_name.c_str());
    if (1 != EVP_DecryptInit_ex(ctx, evp_cipher, nullptr, key_bytes.data(), iv_bytes.data())) {
        return {false, {}};
    }

    // 3.Provide the message to be decrypted and obtain the plaintext output
    int    len;
    byte_t decrypted_txt_bytes[1024];
    if (1 !=
        EVP_DecryptUpdate(
            ctx, decrypted_txt_bytes, &len, cipher_text_bytes.data(), cipher_text_bytes.size())) {
        return {false, {}};
    }
    int plaintext_len = len;

    // 4.Finalize the decryption
    if (1 != EVP_DecryptFinal_ex(ctx, decrypted_txt_bytes + len, &len)) {
        return {false, {}};
    }
    plaintext_len += len;

    // 5.Clean up
    EVP_CIPHER_CTX_free(ctx);

    // 6.Return
    std::vector<byte_t> result(plaintext_len);
    memcpy(result.data(), decrypted_txt_bytes, plaintext_len);

    return {true, result};
}
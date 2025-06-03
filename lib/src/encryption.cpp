// lib includes
#include <aes_demo/encryption.h>

// GNU C library includes
#include <openssl/rand.h>

// C++ includes
#include <cstring>
#include <vector>

// relative includes
#include "common.h"

using byte_t = unsigned char;

//! Encrypt
static std::pair<bool, std::vector<byte_t>> __encrypt(const std::vector<byte_t>& cipher_text_bytes,
                                                      const std::vector<byte_t>& key_bytes,
                                                      const std::vector<byte_t>& iv_bytes,
                                                      Cipher                     cipher);

//! Encrypt string message (to base64) which was encrypted using salt and AES
std::pair<bool, std::string> aes_with_salt_encrypt(const std::string& input,
                                                   Cipher             cipher,
                                                   Digest             digest,
                                                   const std::string& password) {
    // 1.Generate random salt
    const int salt_sz = 8;
    byte_t    salt[salt_sz];
    if (1 != RAND_bytes(salt, salt_sz)) {
        return {false, ""};
    }

    // 2.Get key and iv from password due to salt
    std::pair<std::vector<byte_t>, std::vector<byte_t>> key_iv =
        get_key_iv_from_pass(salt, salt_sz, password, cipher, digest);
    const std::vector<byte_t>& key = key_iv.first;
    const std::vector<byte_t>& iv  = key_iv.second;

    // 3.Encrypt
    std::vector<byte_t>                  input_raw(input.data(), input.data() + input.length());
    std::pair<bool, std::vector<byte_t>> encryption = __encrypt(input_raw, key, iv, cipher);
    if (!encryption.first) {
        return {false, ""};
    }
    const std::vector<byte_t>& encrypted = encryption.second;

    // 4.Concat prefix ("Salted__"), salt and encrypted binary arrays (OpenSSL enc rules)
    const std::string   prefix = "Salted__";
    std::vector<byte_t> prefix_raw(prefix.data(), prefix.data() + prefix.length());

    std::vector<byte_t> concated(prefix_raw.size() + salt_sz + encrypted.size());
    memcpy(concated.data(), prefix_raw.data(), prefix_raw.size());
    memcpy(concated.data() + prefix_raw.size(), salt, salt_sz);
    memcpy(concated.data() + prefix_raw.size() + salt_sz, encrypted.data(), encrypted.size());

    // 5.Encode it to base64
    std::string encrypted_base64 = bytes_to_str_base64(concated);
    return {true, encrypted_base64};
}

std::pair<bool, std::vector<byte_t>> __encrypt(const std::vector<byte_t>& cipher_text_bytes,
                                               const std::vector<byte_t>& key_bytes,
                                               const std::vector<byte_t>& iv_bytes,
                                               Cipher                     cipher) {
    // 1.Create and initialize the context
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (ctx == nullptr) {
        return {false, {}};
    }

    // 2.Initialize the encryption operation
    const std::string cipher_name = get_cipher_name(cipher);
    const EVP_CIPHER* evp_cipher  = EVP_get_cipherbyname(cipher_name.c_str());
    if (1 != EVP_EncryptInit_ex(ctx, evp_cipher, nullptr, key_bytes.data(), iv_bytes.data())) {
        return {false, {}};
    }

    // 3.Provide the message to be encrypted and obtain the plaintext output
    int    len;
    byte_t encrypted_txt_bytes[1024];
    if (1 !=
        EVP_EncryptUpdate(
            ctx, encrypted_txt_bytes, &len, cipher_text_bytes.data(), cipher_text_bytes.size())) {
        return {false, {}};
    }
    int encrypted_txt_len = len;

    // 4.Finalize the encryption
    if (1 != EVP_EncryptFinal_ex(ctx, encrypted_txt_bytes + len, &len)) {
        return {false, {}};
    }
    encrypted_txt_len += len;

    // 5.Clean up
    EVP_CIPHER_CTX_free(ctx);

    // 6.Return
    std::vector<byte_t> result(encrypted_txt_len);
    memcpy(result.data(), encrypted_txt_bytes, encrypted_txt_len);

    return {true, result};
}
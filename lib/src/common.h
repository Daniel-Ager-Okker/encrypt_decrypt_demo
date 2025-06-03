#ifndef COMMON_H
#define COMMON_H

#include <string>
#include <vector>

#include <aes_demo/params.h>

/**
 * Get cipher name from enum value
 * @param cipher enum value
 * @return cipher name
 */
std::string get_cipher_name(Cipher cipher);

/**
 * Extract key and iv from password due to salt
 * @param salt salt
 * @param salt_sz salt size
 * @param pass password
 * @param cipher cipher
 * @param digest digest
 * @return a pair of key and iv as std::vectors
 */
std::pair<std::vector<unsigned char>, std::vector<unsigned char>>
get_key_iv_from_pass(const unsigned char* salt,
                     const int            salt_sz,
                     const std::string&   pass,
                     Cipher               cipher,
                     Digest               digest);

/**
 * Get raw bytes from string base64 format
 * @param encoded_str_base64 input in string base64 format
 * @return raw bytes as vector
 */
std::vector<unsigned char> str_base64_to_bytes(const std::string& encoded_str_base64);

/**
 * Get string in base64 format from raw bytes
 * @param bytes raw bytes
 * @return string in base64 fromat
 */
std::string bytes_to_str_base64(const std::vector<unsigned char>& bytes);

#endif

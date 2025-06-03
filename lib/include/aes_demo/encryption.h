#ifndef ENCRYPTION_H
#define ENCRYPTION_H

#include <string>

#include "params.h"

/**
 * Encrypt string message (to base64) which was encrypted using salt and AES
 * @param input input string
 * @param cipher cipher that must be used for encryption
 * @param digest digest that must be used for encryption
 * @param password password that must be used for decryption
 * @return encrypted string message (in base64 format) with success flag
 */
std::pair<bool, std::string> aes_with_salt_encrypt(const std::string& input,
                                                   Cipher             cipher,
                                                   Digest             digest,
                                                   const std::string& password);

#endif
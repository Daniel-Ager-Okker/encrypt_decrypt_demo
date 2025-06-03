#ifndef DECRYPTION_H
#define DECRYPTION_H

#include <string>

#include "params.h"

/**
 * Decrypt string message which was encrypted using salt and AES
 * @param input_base64 encoded input in base64 format
 * @param cipher cipher that must be used for decryption
 * @param digest digest that must be used for decryption
 * @param password password that must be used for decryption
 * @return decrypted string message with success flag
 */
std::pair<bool, std::string> aes_with_salt_decrypt(const std::string& input_base64,
                                                   Cipher             cipher,
                                                   Digest             digest,
                                                   const std::string& password);

#endif
#include <gtest/gtest.h>

#include <aes_demo/decryption.h>
#include <aes_demo/encryption.h>

#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <sstream>

static const std::string PASSWORD   = "some_password";
constexpr Cipher         CIPHER     = Cipher::AES_256_CBC;
constexpr Digest         DIGEST     = Digest::SHA256;
constexpr int            ITER_COUNT = 1000;

//! Get cipher txt value
static std::string __cipher_to_txt();

//! Get digest txt value
static std::string __digest_to_txt();

//! Get path to directory where placed binary executable
static std::filesystem::path __get_directory_path();

//! Read string from file
static std::string read_data_from_file(const std::filesystem::path& pth);

TEST(MainSuite, EncryptDecrypt) {
    /**
     * Scenario:
     * 1.Encrypt message due to library
     * 2.Decrypt it due to library
     * 3.Compare original message with decrypted
     */

    const std::string message = "Hello, world!";

    // 1.Use library for encrypt
    const std::pair<bool, std::string> encryption =
        aes_with_salt_encrypt(message, CIPHER, DIGEST, PASSWORD);

    ASSERT_TRUE(encryption.first);
    const std::string& encrypted = encryption.second;

    // 2.Use library for decrypt
    std::pair<bool, std::string> decryption =
        aes_with_salt_decrypt(encrypted, CIPHER, DIGEST, PASSWORD);

    ASSERT_TRUE(decryption.first);

    // 3.Compare
    ASSERT_EQ(message, decryption.second);
}

TEST(MainSuite, EncryptOpenSSLAndDecrypt) {
    /**
     * Scenario:
     * 1.Encrypt message due to OpenSSL enc utility
     * 2.Decrypt it due to library
     * 3.Compare original message with decrypted
     */

    // 1.Put message into the temp file
    const std::string message = "Hello, world!";

    const std::filesystem::path dir_path      = __get_directory_path();
    const std::filesystem::path tmp_file_path = dir_path / "message.txt";

    std::ofstream file(tmp_file_path);
    if (!file) {
        std::cerr << "Can'r create tmp file\n";
        exit(-1);
    }
    file << message;
    file.close();

    // 1.Use OpenSSL enc executable for encrypt

    // 1.1.Prepare command
    std::ostringstream cmd_ss;
    cmd_ss << "openssl enc -e ";
    cmd_ss << '-' << __cipher_to_txt() << ' ';
    cmd_ss << "-base64 -p -pbkdf2 ";
    cmd_ss << "-pass pass:" << PASSWORD << ' ';
    cmd_ss << "-md " << __digest_to_txt() << ' ';
    cmd_ss << "-iter " << ITER_COUNT << ' ';
    cmd_ss << "-salt ";
    cmd_ss << "-in " << tmp_file_path.c_str() << ' ';
    cmd_ss << "-out " << (dir_path / "encrypted.txt").c_str();

    std::string cmd = cmd_ss.str();

    // 1.2.Execute
    int executed = system(cmd.c_str());
    if (0 != executed) {
        std::cerr << "Error while using OpenSSL enc\n";
        exit(-1);
    }

    // 2.Read encrypted data
    std::string encrypted = read_data_from_file(dir_path / "encrypted.txt");

    // 3.Decrypt
    std::pair<bool, std::string> decryption =
        aes_with_salt_decrypt(encrypted, CIPHER, DIGEST, PASSWORD);

    ASSERT_TRUE(decryption.first);
    ASSERT_EQ(message, decryption.second);

    // 4.Clean artifacts
    std::filesystem::remove(tmp_file_path);
    std::filesystem::remove(dir_path / "encrypted.txt");
}

TEST(MainSuite, EncryptAndDecryptOpenSSL) {
    /**
     * Scenario:
     * 1.Encrypt message due to library
     * 2.Decrypt it due to OpenSSL enc utility
     * 3.Compare original message with decrypted
     */

    const std::string message = "Hello, world!";

    // 1.Use library function
    const std::pair<bool, std::string> encryption =
        aes_with_salt_encrypt(message, CIPHER, DIGEST, PASSWORD);

    ASSERT_TRUE(encryption.first);
    const std::string& encrypted = encryption.second;

    // 2.Create tmp file and set encrypted data to it
    const std::filesystem::path dir_path      = __get_directory_path();
    const std::filesystem::path tmp_file_path = dir_path / "encrypted.txt";

    std::ofstream file(tmp_file_path);
    if (!file) {
        std::cerr << "Can't create tmp file\n";
        exit(-1);
    }
    file << encrypted << std::endl;
    file.close();

    // 3.Use OpenSSL enc executable for decrypt

    // 3.1.Prepare command
    std::ostringstream cmd_ss;
    cmd_ss << "openssl enc -d ";
    cmd_ss << '-' << __cipher_to_txt() << ' ';
    cmd_ss << "-base64 -p -pbkdf2 ";
    cmd_ss << "-pass pass:" << PASSWORD << ' ';
    cmd_ss << "-md " << __digest_to_txt() << ' ';
    cmd_ss << "-iter " << ITER_COUNT << ' ';
    cmd_ss << "-salt ";
    cmd_ss << "-in " << tmp_file_path.c_str() << ' ';
    cmd_ss << "-out " << (dir_path / "decrypted.txt").c_str();

    std::string cmd = cmd_ss.str();

    // 3.2.Execute
    int executed = system(cmd.c_str());

    // 4.Read decrypted and compare
    const std::string decrypted = read_data_from_file(dir_path / "decrypted.txt");
    ASSERT_EQ(message, decrypted);

    std::filesystem::remove(tmp_file_path);
    std::filesystem::remove(dir_path / "decrypted.txt");
}

int main(int argc, char** argv) {
    ::testing::InitGoogleTest(&argc, argv);

    return RUN_ALL_TESTS();
}

std::string __cipher_to_txt() {
    switch (CIPHER) {
        case Cipher::AES_128_CBC:
            return "aes-128-cbc";
        case Cipher::AES_256_CBC:
            return "aes-256-cbc";
        default:
            return "NONE";
    }
}

std::string __digest_to_txt() {
    switch (DIGEST) {
        case Digest::SHA256:
            return "sha256";
        default:
            return "NONE";
    }
}

std::filesystem::path __get_directory_path() {
    return std::filesystem::current_path();
}

std::string read_data_from_file(const std::filesystem::path& pth) {
    std::ifstream fileStream(pth);
    if (!fileStream) {
        std::cerr << "Can't open file " << pth << '\n';
        exit(-1);
    }

    std::ostringstream buffer;
    buffer << fileStream.rdbuf();

    std::string data = buffer.str();

    if (data.back() == '\n') {
        data.pop_back();
    }

    return data;
}

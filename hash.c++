#include <iostream>
#include <openssl/evp.h>
#include <cstring>

void generate_hash(const std::string &text, const std::string &algorithm) {
    const EVP_MD *md = EVP_get_digestbyname(algorithm.c_str());
    if (md == nullptr) {
        std::cerr << "Unknown algorithm: " << algorithm << std::endl;
        return;
    }

    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(mdctx, md, nullptr);

    EVP_DigestUpdate(mdctx, text.c_str(), text.size());

    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int hash_len;
    EVP_DigestFinal_ex(mdctx, hash, &hash_len);

    EVP_MD_CTX_free(mdctx);

    std::cout << "Hash: ";
    for (unsigned int i = 0; i < hash_len; i++)
        printf("%02x", hash[i]);
    std::cout << std::endl;
}

int main() {
    std::string text, algorithm;

    std::cout << "Enter text to hash: ";
    std::getline(std::cin, text);

    std::cout << "Enter hash algorithm (default sha256): ";
    std::getline(std::cin, algorithm);

    if (algorithm.empty()) algorithm = "sha256";

    generate_hash(text, algorithm);

    return 0;
}

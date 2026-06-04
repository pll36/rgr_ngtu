#ifndef MY_CIPHERS_H
#define MY_CIPHERS_H

#include <string>
#include <cstdint>

struct TeaKey
{
    uint32_t values[4];
};

// Columnar transposition (Unicode-safe: works with UTF-8 via UTF-32 internally)
std::string encryptColumnar(
    const std::string& text,
    const std::string& key);

std::string decryptColumnar(
    const std::string& text,
    const std::string& key);

// TEA block cipher
std::string encryptTEA(
    const std::string& text,
    const TeaKey& key);

std::string decryptTEA(
    const std::string& text,
    const TeaKey& key);

#endif

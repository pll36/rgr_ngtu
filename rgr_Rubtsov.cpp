#include "rgr_Rubtsov.h"
#include <vector>
#include <algorithm>
#include <cctype>

// ============================================
//  ВСПОМОГАТЕЛЬНЫЕ МАТЕМАТИЧЕСКИЕ ФУНКЦИИ
// ============================================

static int findModularInverse(int number, int modulo)
{
    int original_modulo = modulo;
    int x0 = 0, x1 = 1;
    int a = number, b = modulo;

    while (a > 1)
    {
        int quotient = a / b;
        int temp = b;
        b = a % b;
        a = temp;

        int x_temp = x1;
        x1 = x0 - quotient * x1;
        x0 = x_temp;
    }

    if (x1 < 0)
    {
        x1 += original_modulo;
    }

    return x1;
}

static int greatestCommonDivisor(int first, int second)
{
    while (second != 0)
    {
        int temp = second;
        second = first % second;
        first = temp;
    }

    return first;
}

// ============================================
//  АФФИННЫЙ ШИФР (ПОБАЙТОВЫЙ)
// ============================================

bool initializeAffineKey(AffineKey& key, int a, int b, int modulus)
{
    if (modulus <= 0)
    {
        return false;
    }

    key.coefficient_a = a % modulus;
    if (key.coefficient_a < 0)
    {
        key.coefficient_a += modulus;
    }

    key.coefficient_b = b % modulus;
    if (key.coefficient_b < 0)
    {
        key.coefficient_b += modulus;
    }

    key.modulus = modulus;

    if (greatestCommonDivisor(key.coefficient_a, modulus) != 1)
    {
        return false;
    }

    key.inverse_a = findModularInverse(key.coefficient_a, modulus);

    return true;
}

std::string encryptAffine(const std::string& text, const AffineKey& key)
{
    std::string result;
    result.reserve(text.size());

    for (unsigned char byte : text)
    {
        int numeric_value = static_cast<int>(byte);
        int encrypted_value = (key.coefficient_a * numeric_value + key.coefficient_b) % key.modulus;

        if (encrypted_value < 0)
        {
            encrypted_value += key.modulus;
        }

        result += static_cast<char>(encrypted_value);
    }

    return result;
}

std::string decryptAffine(const std::string& text, const AffineKey& key)
{
    std::string result;
    result.reserve(text.size());

    for (unsigned char byte : text)
    {
        int numeric_value = static_cast<int>(byte);
        int decrypted_value = key.inverse_a * (numeric_value - key.coefficient_b);
        decrypted_value %= key.modulus;

        if (decrypted_value < 0)
        {
            decrypted_value += key.modulus;
        }

        result += static_cast<char>(decrypted_value);
    }

    return result;
}

std::string processAffine(const std::string& text, const AffineKey& key, bool mode)
{
    if (mode)
    {
        return encryptAffine(text, key);
    }
    else
    {
        return decryptAffine(text, key);
    }
}

// ============================================
//  ШИФР ВИЖЕНЕРА (ПОБАЙТОВЫЙ)
// ============================================

static std::string prepareVigenereKeyBytes(const std::string& text, const std::string& keyword)
{
    std::string result;
    size_t keywordIndex = 0;
    size_t keywordLength = keyword.length();

    if (keywordLength == 0)
    {
        return result;
    }

    result.reserve(text.size());

    for (size_t i = 0; i < text.size(); ++i)
    {
        result += keyword[keywordIndex % keywordLength];
        ++keywordIndex;
    }

    return result;
}

std::string encryptVigenere(const std::string& text, const std::string& keyword)
{
    if (keyword.empty())
    {
        return text;
    }

    std::string extendedKey = prepareVigenereKeyBytes(text, keyword);
    std::string result;
    result.reserve(text.size());

    for (size_t i = 0; i < text.size(); ++i)
    {
        unsigned char textByte = static_cast<unsigned char>(text[i]);
        unsigned char keyByte = static_cast<unsigned char>(extendedKey[i]);

        int encrypted_value = (textByte + keyByte) % 256;
        result += static_cast<char>(encrypted_value);
    }

    return result;
}

std::string decryptVigenere(const std::string& text, const std::string& keyword)
{
    if (keyword.empty())
    {
        return text;
    }

    std::string extendedKey = prepareVigenereKeyBytes(text, keyword);
    std::string result;
    result.reserve(text.size());

    for (size_t i = 0; i < text.size(); ++i)
    {
        unsigned char textByte = static_cast<unsigned char>(text[i]);
        unsigned char keyByte = static_cast<unsigned char>(extendedKey[i]);

        int decrypted_value = textByte - keyByte;
        while (decrypted_value < 0)
        {
            decrypted_value += 256;
        }
        decrypted_value %= 256;

        result += static_cast<char>(decrypted_value);
    }

    return result;
}

std::string processVigenere(const std::string& text, const std::string& keyword, bool encrypt)
{
    if (encrypt)
    {
        return encryptVigenere(text, keyword);
    }
    else
    {
        return decryptVigenere(text, keyword);
    }
}

// ============================================
//  УНИВЕРСАЛЬНАЯ ФУНКЦИЯ ДЛЯ ЛЮБОГО ШИФРА
// ============================================

std::string processCipher(const std::string& text, 
                          const AffineKey& affineKey,
                          const std::string& vigenereKey,
                          CipherType type, 
                          bool encrypt)
{
    if (type == AFFINE_CIPHER)
    {
        return processAffine(text, affineKey, encrypt);
    }
    else // VIGENERE_CIPHER
    {
        return processVigenere(text, vigenereKey, encrypt);
    }
}

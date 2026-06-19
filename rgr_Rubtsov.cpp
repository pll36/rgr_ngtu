#include "rgr_Rubtsov.h"
#include <vector>
#include <algorithm>
#include <cctype>

// ============================================
//  UTF-8 <-> UTF-32 conversion
// ============================================

static std::u32string utf8ToUtf32(const std::string& source)
{
    std::u32string result;
    size_t index = 0;

    while (index < source.size())
    {
        unsigned char byte = static_cast<unsigned char>(source[index]);
        char32_t codepoint = 0;
        int extraBytes = 0;

        if (byte < 0x80)
        {
            codepoint = byte;
            extraBytes = 0;
        }
        else if (byte < 0xC0)
        {
            ++index;
            continue;
        }
        else if (byte < 0xE0)
        {
            codepoint = byte & 0x1F;
            extraBytes = 1;
        }
        else if (byte < 0xF0)
        {
            codepoint = byte & 0x0F;
            extraBytes = 2;
        }
        else if (byte < 0xF8)
        {
            codepoint = byte & 0x07;
            extraBytes = 3;
        }
        else
        {
            ++index;
            continue;
        }

        ++index;

        for (int extra = 0; extra < extraBytes; ++extra)
        {
            if (index >= source.size())
            {
                break;
            }

            unsigned char continuation = static_cast<unsigned char>(source[index]);
            if ((continuation & 0xC0) != 0x80)
            {
                break;
            }
            codepoint = (codepoint << 6) | (continuation & 0x3F);
            ++index;
        }

        result += codepoint;
    }

    return result;
}

static std::string utf32ToUtf8(const std::u32string& source)
{
    std::string result;

    for (char32_t codepoint : source)
    {
        if (codepoint < 0x80)
        {
            result += static_cast<char>(codepoint);
        }
        else if (codepoint < 0x800)
        {
            result += static_cast<char>(0xC0 | (codepoint >> 6));
            result += static_cast<char>(0x80 | (codepoint & 0x3F));
        }
        else if (codepoint < 0x10000)
        {
            result += static_cast<char>(0xE0 | (codepoint >> 12));
            result += static_cast<char>(0x80 | ((codepoint >> 6) & 0x3F));
            result += static_cast<char>(0x80 | (codepoint & 0x3F));
        }
        else if (codepoint < 0x110000)
        {
            result += static_cast<char>(0xF0 | (codepoint >> 18));
            result += static_cast<char>(0x80 | ((codepoint >> 12) & 0x3F));
            result += static_cast<char>(0x80 | ((codepoint >> 6) & 0x3F));
            result += static_cast<char>(0x80 | (codepoint & 0x3F));
        }
    }

    return result;
}

// ============================================
//  АФФИННЫЙ ШИФР
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
    std::u32string unicodeText = utf8ToUtf32(text);
    std::u32string unicodeResult;

    for (char32_t codepoint : unicodeText)
    {
        int numeric_value = static_cast<int>(codepoint);
        int encrypted_value = (key.coefficient_a * numeric_value + key.coefficient_b) % key.modulus;

        if (encrypted_value < 0)
        {
            encrypted_value += key.modulus;
        }

        unicodeResult += static_cast<char32_t>(encrypted_value);
    }

    return utf32ToUtf8(unicodeResult);
}

std::string decryptAffine(const std::string& text, const AffineKey& key)
{
    std::u32string unicodeText = utf8ToUtf32(text);
    std::u32string unicodeResult;

    for (char32_t codepoint : unicodeText)
    {
        int numeric_value = static_cast<int>(codepoint);
        int decrypted_value = key.inverse_a * (numeric_value - key.coefficient_b);
        decrypted_value %= key.modulus;

        if (decrypted_value < 0)
        {
            decrypted_value += key.modulus;
        }

        unicodeResult += static_cast<char32_t>(decrypted_value);
    }

    return utf32ToUtf8(unicodeResult);
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
//  ШИФР ВИЖЕНЕРА
// ============================================

static std::u32string prepareVigenereKey(const std::u32string& text, const std::u32string& keyword)
{
    std::u32string result;
    size_t keywordIndex = 0;
    size_t keywordLength = keyword.length();

    if (keywordLength == 0)
    {
        return result;
    }

    for (size_t i = 0; i < text.length(); ++i)
    {
        result += keyword[keywordIndex % keywordLength];
        ++keywordIndex;
    }

    return result;
}

std::string encryptVigenere(const std::string& text, const std::string& keyword)
{
    std::u32string unicodeText = utf8ToUtf32(text);
    std::u32string unicodeKeyword = utf8ToUtf32(keyword);
    std::u32string unicodeResult;

    if (unicodeKeyword.empty())
    {
        return text;  // Если ключ пустой, возвращаем исходный текст
    }

    std::u32string extendedKey = prepareVigenereKey(unicodeText, unicodeKeyword);

    for (size_t i = 0; i < unicodeText.size(); ++i)
    {
        char32_t textChar = unicodeText[i];
        char32_t keyChar = extendedKey[i];

        // Простое сложение кодов символов (работает с любыми символами)
        int encrypted_value = static_cast<int>(textChar) + static_cast<int>(keyChar);
        // Ограничиваем диапазон 32-битным числом
        encrypted_value %= 0x110000;

        unicodeResult += static_cast<char32_t>(encrypted_value);
    }

    return utf32ToUtf8(unicodeResult);
}

std::string decryptVigenere(const std::string& text, const std::string& keyword)
{
    std::u32string unicodeText = utf8ToUtf32(text);
    std::u32string unicodeKeyword = utf8ToUtf32(keyword);
    std::u32string unicodeResult;

    if (unicodeKeyword.empty())
    {
        return text;  // Если ключ пустой, возвращаем исходный текст
    }

    std::u32string extendedKey = prepareVigenereKey(unicodeText, unicodeKeyword);

    for (size_t i = 0; i < unicodeText.size(); ++i)
    {
        char32_t textChar = unicodeText[i];
        char32_t keyChar = extendedKey[i];

        // Вычитание кодов символов
        int decrypted_value = static_cast<int>(textChar) - static_cast<int>(keyChar);
        // Ограничиваем диапазон (делаем положительным)
        while (decrypted_value < 0)
        {
            decrypted_value += 0x110000;
        }
        decrypted_value %= 0x110000;

        unicodeResult += static_cast<char32_t>(decrypted_value);
    }

    return utf32ToUtf8(unicodeResult);
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

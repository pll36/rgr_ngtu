#include "rgr_Rubtsov.h"
#include <vector>
#include <algorithm>

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
        else
        {
            codepoint = byte & 0x07;
            extraBytes = 3;
        }

        ++index;

        for (int extra = 0; extra < extraBytes; ++extra)
        {
            if (index >= source.size())
            {
                break;
            }

            unsigned char continuation = static_cast<unsigned char>(source[index]);
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
        else
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
//  Affine cipher core functions
// ============================================

static int findModularInverse(int a, int m)
{
    int m0 = m;
    int y = 0, x = 1;
    if (m == 1) return 0;
    while (a > 1)
    {
        int q = a / m;
        int t = m;
        m = a % m;
        a = t;
        t = y;
        y = x - q * y;
        x = t;
    }
    if (x < 0) x += m0;
    return x;
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

static int mul_mod(int a, int b, int mod)
{
    a %= mod;
    b %= mod;
    int res = 0;
    while (b > 0)
    {
        if (b & 1)
        {
            res += a;
            if (res >= mod) res -= mod;
        }
        a <<= 1;
        if (a >= mod) a -= mod;
        b >>= 1;
    }
    return res;
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
        
        int encrypted_value = (mul_mod(key.coefficient_a, numeric_value, key.modulus) + key.coefficient_b) % key.modulus;

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
        
        int diff = numeric_value - key.coefficient_b;
        diff %= key.modulus;
        if (diff < 0) diff += key.modulus;
        int decrypted_value = mul_mod(key.inverse_a, diff, key.modulus);

        if (decrypted_value < 0)
        {
            decrypted_value += key.modulus;
        }

        unicodeResult += static_cast<char32_t>(decrypted_value);
    }

    return utf32ToUtf8(unicodeResult);
}

// ============================================
//  Шифр Виженера
// ============================================

std::string encryptVigenere(const std::string& text, const std::string& key)
{
    if (key.empty())
    {
        return text; // если ключ пустой, возвращаем текст без изменений
    }

    std::u32string unicodeText = utf8ToUtf32(text);
    std::u32string unicodeKey = utf8ToUtf32(key);
    std::u32string unicodeResult;

    size_t keyIndex = 0;
    size_t keyLength = unicodeKey.size();

    for (char32_t codepoint : unicodeText)
    {
        // Используем код символа ключа как сдвиг (по модулю 0x110000)
        int shift = static_cast<int>(unicodeKey[keyIndex % keyLength]);
        
        // Применяем сдвиг: (codepoint + shift) % 0x110000
        int encrypted_value = (static_cast<int>(codepoint) + shift) % 0x110000;
        
        unicodeResult += static_cast<char32_t>(encrypted_value);
        
        keyIndex++;
    }

    return utf32ToUtf8(unicodeResult);
}

std::string decryptVigenere(const std::string& text, const std::string& key)
{
    if (key.empty())
    {
        return text; // если ключ пустой, возвращаем текст без изменений
    }

    std::u32string unicodeText = utf8ToUtf32(text);
    std::u32string unicodeKey = utf8ToUtf32(key);
    std::u32string unicodeResult;

    size_t keyIndex = 0;
    size_t keyLength = unicodeKey.size();

    for (char32_t codepoint : unicodeText)
    {
        // Используем код символа ключа как сдвиг (по модулю 0x110000)
        int shift = static_cast<int>(unicodeKey[keyIndex % keyLength]);
        
        // Применяем обратный сдвиг: (codepoint - shift + 0x110000) % 0x110000
        int decrypted_value = (static_cast<int>(codepoint) - shift) % 0x110000;
        if (decrypted_value < 0)
        {
            decrypted_value += 0x110000;
        }
        
        unicodeResult += static_cast<char32_t>(decrypted_value);
        
        keyIndex++;
    }

    return utf32ToUtf8(unicodeResult);
}

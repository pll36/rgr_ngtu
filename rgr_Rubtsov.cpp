#include "affine_cipher.h"
#include <cctype>

// Расширенный алгоритм Евклида для нахождения обратного элемента
static int findModularInverse(int number, int modulo)
{
    int original_modulo = modulo;
    int remainder_prev = 0;
    int remainder_current = 1;
    int temp_number = number;
    int temp_modulo = modulo;

    while (temp_number > 1)
    {
        int quotient = temp_number / temp_modulo;
        int temp = temp_modulo;
        temp_modulo = temp_number % temp_modulo;
        temp_number = temp;

        int remainder_next = remainder_prev - quotient * remainder_current;
        remainder_prev = remainder_current;
        remainder_current = remainder_next;
    }

    remainder_current %= original_modulo;

    if (remainder_current < 0)
    {
        remainder_current += original_modulo;
    }

    return remainder_current;
}

// Наибольший общий делитель
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

// Инициализация ключа
bool initializeAffineKey(AffineKey& key, int a, int b, int modulus)
{
    if (modulus <= 0)
    {
        return false;
    }

    key.coefficient_a = a;
    key.coefficient_b = b;
    key.modulus = modulus;

    // Приводим a к диапазону [0, modulus-1]
    key.coefficient_a %= modulus;

    if (key.coefficient_a < 0)
    {
        key.coefficient_a += modulus;
    }

    // Проверяем, что a взаимно просто с modulus
    if (greatestCommonDivisor(key.coefficient_a, modulus) != 1)
    {
        return false;
    }

    key.inverse_a = findModularInverse(key.coefficient_a, modulus);

    return true;
}

// Прямой аффинный шифр
std::string encryptAffine(const std::string& text, const AffineKey& key)
{
    std::string result;

    for (char character : text)
    {
        if (std::isalpha(static_cast<unsigned char>(character)))
        {
            bool is_uppercase = std::isupper(static_cast<unsigned char>(character));
            int base = is_uppercase ? 'A' : 'a';

            int numeric_value = character - base;
            int encrypted_value = (key.coefficient_a * numeric_value + key.coefficient_b) % key.modulus;

            if (encrypted_value < 0)
            {
                encrypted_value += key.modulus;
            }

            result += static_cast<char>(base + encrypted_value);
        }
        else
        {
            result += character;
        }
    }

    return result;
}

// Обратный аффинный шифр
std::string decryptAffine(const std::string& text, const AffineKey& key)
{
    std::string result;

    for (char character : text)
    {
        if (std::isalpha(static_cast<unsigned char>(character)))
        {
            bool is_uppercase = std::isupper(static_cast<unsigned char>(character));
            int base = is_uppercase ? 'A' : 'a';

            int numeric_value = character - base;
            int decrypted_value = (key.inverse_a * (numeric_value - key.coefficient_b)) % key.modulus;

            if (decrypted_value < 0)
            {
                decrypted_value += key.modulus;
            }

            result += static_cast<char>(base + decrypted_value);
        }
        else
        {
            result += character;
        }
    }

    return result;
}

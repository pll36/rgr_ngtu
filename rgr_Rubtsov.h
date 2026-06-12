#ifndef AFFINE_CIPHER_H
#define AFFINE_CIPHER_H

#include <string>

// Структура для хранения параметров аффинного шифра
struct AffineKey {
    int coefficient_a;
    int coefficient_b;
    int modulus;
    int inverse_a;
};

// Инициализация ключа
bool initializeAffineKey(AffineKey& key, int a, int b, int modulus);

// Прямой аффинный шифр (работает с любыми символами, включая русские)
std::string encryptAffine(const std::string& text, const AffineKey& key);

// Обратный аффинный шифр
std::string decryptAffine(const std::string& text, const AffineKey& key);

#endif

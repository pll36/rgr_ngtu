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

// ============================================
// АФФИННЫЙ ШИФР
// ============================================

// Инициализация ключа
bool initializeAffineKey(AffineKey& key, int a, int b, int modulus);

// Прямой аффинный шифр (шифрование) - побайтовое шифрование
std::string encryptAffine(const std::string& text, const AffineKey& key);

// Обратный аффинный шифр (дешифрование) - побайтовое дешифрование
std::string decryptAffine(const std::string& text, const AffineKey& key);

// Универсальная функция с выбором направления
// mode = true  → прямой аффинный шифр (шифрование)
// mode = false → обратный аффинный шифр (дешифрование)
std::string processAffine(const std::string& text, const AffineKey& key, bool mode);

// ============================================
// ШИФР ВИЖЕНЕРА (побайтовый)
// ============================================

// Шифрование Виженера (побайтовое, работает с любыми символами)
std::string encryptVigenere(const std::string& text, const std::string& keyword);

// Дешифрование Виженера (побайтовое)
std::string decryptVigenere(const std::string& text, const std::string& keyword);

// Универсальная функция для Виженера с выбором направления
std::string processVigenere(const std::string& text, const std::string& keyword, bool encrypt);

// ============================================
// ВСПОМОГАТЕЛЬНЫЕ ФУНКЦИИ
// ============================================

// Выбор шифра
enum CipherType {
    AFFINE_CIPHER,
    VIGENERE_CIPHER
};

// Универсальная функция для любого шифра
std::string processCipher(const std::string& text, 
                          const AffineKey& affineKey,
                          const std::string& vigenereKey,
                          CipherType type, 
                          bool encrypt);

#endif

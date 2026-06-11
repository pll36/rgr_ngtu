#ifndef AFFINE_CIPHER_H
#define AFFINE_CIPHER_H

#include <string>

// Структура для хранения параметров аффинного шифра
struct AffineCipher {
    int coefficient_a;
    int coefficient_b;
    int modulus;
    int inverse_a;
};

// Инициализация шифра с проверкой параметров
bool initializeAffineCipher(AffineCipher& cipher);

// Прямой аффинный шифр
std::string forwardAffineCipher(const std::string& text, const AffineCipher& cipher);

// Обратный аффинный шифр
std::string inverseAffineCipher(const std::string& text, const AffineCipher& cipher);

// Главная функция для запуска аффинного шифра из общего main
void runAffineCipher();

#endif

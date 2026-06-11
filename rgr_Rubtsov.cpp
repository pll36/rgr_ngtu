#include "affine_cipher.h"
#include <iostream>
#include <fstream>
#include <cctype>
#include <cstdio>

// Установка русской локали для консоли
static void setRussianConsole() {
    system("chcp 65001 > nul");
    setvbuf(stdout, NULL, _IONBF, 0);
}

// Расширенный алгоритм Евклида для нахождения обратного элемента
static int findModularInverse(int number, int modulo) {
    int original_modulo = modulo;
    int remainder_prev = 0, remainder_current = 1;
    int temp_number = number;
    int temp_modulo = modulo;
    
    while (temp_number > 1) {
        int quotient = temp_number / temp_modulo;
        int temp = temp_modulo;
        temp_modulo = temp_number % temp_modulo;
        temp_number = temp;
        
        int remainder_next = remainder_prev - quotient * remainder_current;
        remainder_prev = remainder_current;
        remainder_current = remainder_next;
    }
    
    remainder_current %= original_modulo;
    if (remainder_current < 0) {
        remainder_current += original_modulo;
    }
    
    return remainder_current;
}

// Проверка взаимной простоты
static bool isCoprime(int number, int modulo) {
    int first = number;
    int second = modulo;
    
    while (second != 0) {
        int temp = second;
        second = first % second;
        first = temp;
    }
    
    return first == 1;
}

// Прямой аффинный шифр
std::string forwardAffineCipher(const std::string& text, const AffineCipher& cipher) {
    std::string result;
    
    for (char character : text) {
        if (std::isalpha(character)) {
            bool is_uppercase = std::isupper(character);
            int base = is_uppercase ? 'A' : 'a';
            
            int numeric_value = character - base;
            int encrypted_value = (cipher.coefficient_a * numeric_value + cipher.coefficient_b) % cipher.modulus;
            
            if (encrypted_value < 0) {
                encrypted_value += cipher.modulus;
            }
            
            result += static_cast<char>(base + encrypted_value);
        } else {
            result += character;
        }
    }
    
    return result;
}

// Обратный аффинный шифр
std::string inverseAffineCipher(const std::string& text, const AffineCipher& cipher) {
    std::string result;
    
    for (char character : text) {
        if (std::isalpha(character)) {
            bool is_uppercase = std::isupper(character);
            int base = is_uppercase ? 'A' : 'a';
            
            int numeric_value = character - base;
            int decrypted_value = (cipher.inverse_a * (numeric_value - cipher.coefficient_b)) % cipher.modulus;
            
            if (decrypted_value < 0) {
                decrypted_value += cipher.modulus;
            }
            
            result += static_cast<char>(base + decrypted_value);
        } else {
            result += character;
        }
    }
    
    return result;
}

// Чтение содержимого файла
static std::string readFile(const std::string& filename) {
    std::ifstream input_file(filename);
    if (!input_file.is_open()) {
        std::cout << "Ошибка: не удалось открыть файл " << filename << std::endl;
        return "";
    }
    
    std::string content;
    std::string line;
    while (std::getline(input_file, line)) {
        content += line + "\n";
    }
    
    if (!content.empty() && content.back() == '\n') {
        content.pop_back();
    }
    
    input_file.close();
    return content;
}

// Запись в файл
static bool writeFile(const std::string& filename, const std::string& content) {
    std::ofstream output_file(filename);
    if (!output_file.is_open()) {
        std::cout << "Ошибка: не удалось создать файл " << filename << std::endl;
        return false;
    }
    
    output_file << content;
    output_file.close();
    return true;
}

// Очистка входного потока
static void clearInputStream() {
    std::cin.clear();
    std::cin.ignore(10000, '\n');
}

// Инициализация шифра
bool initializeAffineCipher(AffineCipher& cipher) {
    std::cout << "Введите размер алфавита (модуль, например 26): ";
    std::cin >> cipher.modulus;
    
    if (cipher.modulus <= 0) {
        std::cout << "Ошибка: модуль должен быть положительным!" << std::endl;
        return false;
    }
    
    std::cout << "Введите коэффициент a (должен быть взаимно прост с " << cipher.modulus << "): ";
    std::cin >> cipher.coefficient_a;
    
    if (!isCoprime(cipher.coefficient_a, cipher.modulus)) {
        std::cout << "Ошибка: a должен быть взаимно прост с модулем!" << std::endl;
        return false;
    }
    
    std::cout << "Введите коэффициент b: ";
    std::cin >> cipher.coefficient_b;
    
    cipher.inverse_a = findModularInverse(cipher.coefficient_a, cipher.modulus);
    
    std::cout << "\nПараметры шифра:" << std::endl;
    std::cout << "a = " << cipher.coefficient_a << std::endl;
    std::cout << "b = " << cipher.coefficient_b << std::endl;
    std::cout << "m = " << cipher.modulus << std::endl;
    std::cout << "a^(-1) mod m = " << cipher.inverse_a << std::endl;
    std::cout << "Обратный шифр: D(y) = " << cipher.inverse_a << " * (y - " << cipher.coefficient_b << ") mod " << cipher.modulus << std::endl;
    
    return true;
}

// Создание тестового файла если его нет
static void createTestFileIfNotExists() {
    std::ifstream check("input.txt");
    if (!check.is_open()) {
        std::cout << "Файл input.txt не найден. Создаю автоматически..." << std::endl;
        std::ofstream create("input.txt");
        if (create.is_open()) {
            create << "BURMALDA";
            create.close();
            std::cout << "Файл input.txt создан с тестовым текстом!" << std::endl;
        }
    } else {
        check.close();
    }
}

// Главная функция для запуска аффинного шифра
void runAffineCipher() {
    setRussianConsole();
    
    std::cout << "\n========================================" << std::endl;
    std::cout << "        АФФИННЫЙ ШИФР И ОБРАТНЫЙ ШИФР" << std::endl;
    std::cout << "========================================" << std::endl;
    std::cout << std::endl;
    
    createTestFileIfNotExists();
    
    AffineCipher cipher;
    
    while (true) {
        if (initializeAffineCipher(cipher)) {
            break;
        }
        std::cout << "Повторите ввод!" << std::endl;
        clearInputStream();
    }
    
    std::cout << std::endl;
    
    std::string file_content = readFile("input.txt");
    
    if (file_content.empty()) {
        std::cout << "Ошибка: файл input.txt пуст или не существует!" << std::endl;
        return;
    }
    
    std::cout << "Содержимое файла input.txt:" << std::endl;
    std::cout << "----------------------------------------" << std::endl;
    std::cout << file_content << std::endl;
    std::cout << "----------------------------------------" << std::endl;
    std::cout << std::endl;
    
    int choice;
    while (true) {
        std::cout << "\n========================================" << std::endl;
        std::cout << "Выберите действие:" << std::endl;
        std::cout << "1 - Применить ПРЯМОЙ аффинный шифр" << std::endl;
        std::cout << "2 - Применить ОБРАТНЫЙ аффинный шифр" << std::endl;
        std::cout << "3 - Выйти в главное меню" << std::endl;
        std::cout << "Ваш выбор: ";
        
        std::cin >> choice;
        clearInputStream();
        
        if (choice == 1) {
            std::string encrypted = forwardAffineCipher(file_content, cipher);
            std::string encrypted_filename = "affine_encrypted.txt";
            
            if (writeFile(encrypted_filename, encrypted)) {
                std::cout << "\nПрямое шифрование завершено!" << std::endl;
                std::cout << "Зашифрованный текст сохранён в файл: " << encrypted_filename << std::endl;
                std::cout << "\nРезультат шифрования:" << std::endl;
                std::cout << "----------------------------------------" << std::endl;
                std::cout << encrypted << std::endl;
                std::cout << "----------------------------------------" << std::endl;
            }
            
        } else if (choice == 2) {
            std::string inversed = inverseAffineCipher(file_content, cipher);
            std::string inversed_filename = "affine_inversed.txt";
            
            if (writeFile(inversed_filename, inversed)) {
                std::cout << "\nОбратное шифрование завершено!" << std::endl;
                std::cout << "Результат сохранён в файл: " << inversed_filename << std::endl;
                std::cout << "\nРезультат обратного шифра:" << std::endl;
                std::cout << "----------------------------------------" << std::endl;
                std::cout << inversed << std::endl;
                std::cout << "----------------------------------------" << std::endl;
            }
            
        } else if (choice == 3) {
            std::cout << "Выход в главное меню..." << std::endl;
            break;
            
        } else {
            std::cout << "Ошибка: введите 1, 2 или 3!" << std::endl;
        }
    }
}

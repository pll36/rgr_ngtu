#include "rgr_Miskova.h" // Подключает заголовочный файл rgr_Miskova.h, в котором объявлены функции encryptShamir, decryptShamir, encryptRSA, decryptRSA
#include <sstream> // Подключает заголовочный файл для работы с строковыми потоками (std::istringstream), который используется для разбора шифротекста (чтения чисел из строки)
#include <stdexcept> // Подключает заголовок для стандартных исключений (std::invalid_argument, std::runtime_error), которые выбрасываются при ошибках (неверные параметры, неподходящий модуль)
#include <string>

using namespace std;

// Быстрое возведение в степень по модулю: (base^exp) % mod
static int modpow(int base, int exp, int mod) { // static ограничивает видимость функции только данным файлом 
    int result = 1;
    base = base % mod;
    while (exp > 0) {
        if (exp & 1) { // Проверяет младший бит exp. Если он равен 1 (т.е. exp нечётное), то нужно умножить текущий результат на base
            result = (result * base) % mod; // Если бит установлен, умножаем result на base и сразу берём по модулю mod
        }
        base = (base * base) % mod; // Возводим base в квадрат по модулю mod
        exp >>= 1; // Сдвигаем exp вправо на один бит (деление на 2), чтобы обработать следующий бит на следующей итерации
    }
    return result;
}

// Шифр Шамира
string encryptShamir(const string& plaintext, int modulus, int key_enc) { // Функция шифрования
    if (modulus <= 0 || key_enc <= 0) { // Проверяет, что модуль и ключ положительные. Иначе выбросить исключение
        throw invalid_argument("Модуль и ключ должны быть положительными"); // Генерирует исключение invalid_argument с поясняющим сообщением
    }

    string ciphertext; // Объявляет пустую строку ciphertext, в которую будет накапливаться результат (каждое зашифрованное число на своей строке)
    for (unsigned char ch : plaintext) { // Цикл, который проходит по каждому символу (байту) исходной строки plaintext. ch имеет тип unsigned char, чтобы значение байта было от 0 до 255
        int byte_val = static_cast<int>(ch); // Преобразует беззнаковый байт в int для дальнейших арифметических операций
        if (byte_val >= modulus) { // Проверяет, не превышает ли значение байта модуль. Если да, то шифрование невозможно, так как возведение по модулю приведёт к потере информации
            throw runtime_error("Значение байта открытого текста >= модуля. Увеличьте модуль (должен быть > 255)."); // Выбрасывает исключение runtime_error с сообщением, что модуль слишком мал
        }
        int enc = modpow(byte_val, key_enc, modulus); // Вычисляет зашифрованное число: (byte_val ^ key_enc) mod modulus с помощью функции modpow
        ciphertext += to_string(enc) + "\n"; // В строку-накопитель ciphertext добавляется число в десятичном виде и после него перевод строки
    }
    return ciphertext; // Возвращает готовую строку шифротекста
}

string decryptShamir(const string& ciphertext, int modulus, int key_dec) { // Функция расшифрования
    if (modulus <= 0 || key_dec <= 0) {
        throw invalid_argument("Модуль и ключ должны быть положительными");
    }

    istringstream iss(ciphertext); // Создаёт объект istringstream из строки ciphertext. Это позволяет читать числа из строки, как из файла
    string plaintext; // Пустая строка для накопления расшифрованных байтов
    string line; // Временная переменная для хранения каждой прочитанной строки
    while (getline(iss, line)) { // Цикл, который читает из потока iss по одной строке до тех пор, пока строки не кончатся. getline записывает прочитанную строку
        if (line.empty()) continue; // Если строка пустая пропускаем её и переходим к следующей итерации
        int enc_num = stoi(line); // Преобразует строку line в целое число (stoi). Это зашифрованное число
        int dec = modpow(enc_num, key_dec, modulus); // Расшифровывает 
        plaintext.push_back(static_cast<char>(dec)); // Преобразует полученное число в char и добавляет в конец строки plaintext
    }
    return plaintext;
}

// Шифр RSA
string encryptRSA(const string& plaintext, int modulus, int key_enc) { // Функция шифрования 
    if (modulus <= 0 || key_enc <= 0) {
        throw invalid_argument("Модуль и ключ должны быть положительными");
    }

    string ciphertext;
    for (unsigned char ch : plaintext) { // Цикл, который проходит по каждому символу (байту) исходной строки plaintext
        int byte_val = static_cast<int>(ch); // Преобразует беззнаковый байт в int для дальнейших арифметических операций
        if (byte_val >= modulus) { // Проверяет, не превышает ли значение байта модуль
            throw runtime_error("Значение байта открытого текста >= модуля. Увеличьте модуль (p*q > 255).");
        }
        int enc = modpow(byte_val, key_enc, modulus); // Вычисляет зашифрованное число
        ciphertext += to_string(enc) + "\n"; // В строку-накопитель ciphertext добавляется число в десятичном виде и после него перевод строки
    }
    return ciphertext;
}

string decryptRSA(const string& ciphertext, int modulus, int key_dec) { // Функция расшифрования 
    if (modulus <= 0 || key_dec <= 0) {
        throw invalid_argument("Модуль и ключ должны быть положительными");
    }

    istringstream iss(ciphertext); // Создаёт объект istringstream из строки ciphertext. Это позволяет читать числа из строки, как из файла
    string plaintext; // Пустая строка для накопления расшифрованных байтов
    string line; // Временная переменная для хранения каждой прочитанной строки
    while (getline(iss, line)) { // Цикл, который читает из потока iss по одной строке до тех пор, пока строки не кончатся. getline записывает прочитанную строку
        if (line.empty()) continue;
        int enc_num = stoi(line); // Преобразует строку line в целое число (stoi). Это зашифрованное число
        int dec = modpow(enc_num, key_dec, modulus); // Расшифровывает
        plaintext.push_back(static_cast<char>(dec)); // Преобразует полученное число в char и добавляет в конец строки plaintext
    }
    return plaintext;
}
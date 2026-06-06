#include <iostream>
#include <locale.h>
#include <fstream>

using namespace std;

// Функция быстрого возведения в степень по модулю (base^exp % mod)
int modpow(int base, int exp, int mod) {
    int result = 1;
    base = base % mod;
    while (exp > 0) {
        if (exp & 1) {
            result = (result * base) % mod;
        }
        base = (base * base) % mod;
        exp >>= 1;
    }
    return result;
}

int main() {
    setlocale(LC_ALL, "ru");
    int choice;
    cout << "Выберите шифр:" << endl;
    cout << "1 - Шамира" << endl;
    cout << "2 - RSA" << endl;
    cin >> choice;

    switch (choice) {
    case 1: { // Шифр Шамира
        int modul, key_sh, key_r;

        cout << "Введите простое число(<255) для модуля (modul): ";
        cin >> modul;
        cout << "Введите ключ шифрования (key_sh): ";
        cin >> key_sh;
        cout << "Введите ключ расшифрования (key_r): ";
        cin >> key_r;

        // Проверка согласованности ключей
        if ((key_sh * key_r) % (modul - 1) != 1) {
            cout << "Ошибка: key_sh * key_r mod (modul-1) != 1. Шифр не сможет правильно расшифровать." << endl;
            break;
        }

        //Шифрование файла
        {
            ifstream in("input.txt", ios::binary); // Открываем исходный файл в бинарном режиме (ios::binary), чтобы читать байты без преобразований; ifstream - Используется для чтения данных из файла
            if (!in.is_open()) { // is_open() – проверка, открыт ли файл успешно, !in.is_open() возвращает true, если файл не открыт
                cout << "Ошибка: не удалось открыть input.txt" << endl;
                break;
            }
            ofstream out("Shamir_encrypted.txt"); // ofstream - Используется для записи данных в файл
            if (!out.is_open()) { // is_open() – проверка, открыт ли файл успешно, !in.is_open() возвращает true, если файл не открыт
                cout << "Ошибка: не удалось создать Shamir_encrypted.txt" << endl;
                break;
            }

            // Читаем файл побайтово. in.get(ch) извлекает очередной символ (байт) в переменную ch
            char ch;
            while (in.get(ch)) {
                unsigned char byte = static_cast<unsigned char>(ch); // Преобразуем в unsigned char, чтобы значение байта было от 0 до 255; static_cast - преобразование типа
                int number_en = static_cast<int>(byte); // Приводим к int number_en – целое число, которое будем шифровать
                if (number_en >= modul) {
                    cout << "Ошибка: байт " << number_en << " >= modul " << modul << ". Невозможно зашифровать." << endl;
                    cout << "Увеличьте модуль (должен быть больше 255)." << endl;
                    in.close(); // закрываем input.txt, из которого читали исходные байты
                    out.close(); // закрываем Shamir_encrypted.txt, в который записывали шифротекст
                    break;
                }
                int encrypted = modpow(number_en, key_sh, modul); // Вычисляем зашифрованное число: number_en^key_sh mod modul
                out << encrypted << endl; // Записываем его в файл encrypted.txt в виде десятичной строки, затем перевод строки
            }
            in.close(); // закрываем input.txt, из которого читали исходные байты
            out.close(); /// закрываем Shamir_encrypted.txt, в который записывали шифротекст
            cout << "Шифрование завершено: input.txt -> Shamir_encrypted.txt" << endl;
        }

        // Расшифрование файла
        {
            ifstream in("Shamir_encrypted.txt"); // Открываем Shamir_encrypted.txt для чтения чисел (текстовый режим); ifstream - Используется для чтения данных из файла
            if (!in.is_open()) { // is_open() – проверка, открыт ли файл успешно, !in.is_open() возвращает true, если файл не открыт
                cout << "Ошибка: не удалось открыть Shamir_encrypted.txt" << endl;
                break;
            }
            ofstream out("Shamir_decrypted.txt", ios::binary); // Открываем decrypted.txt для записи восстановленных байтов в бинарном режиме; // ofstream - Используется для записи данных в файл
            if (!out.is_open()) { // is_open() – проверка, открыт ли файл успешно, !in.is_open() возвращает true, если файл не открыт
                cout << "Ошибка: не удалось создать Shamir_decrypted.txt" << endl;
                break;
            }

            int encrypted_num;
            while (in >> encrypted_num) { // in >> encrypted_num читает очередное целое число из файла (останавливаясь на пробеле или переводе строки)
                int decrypted = modpow(encrypted_num, key_r, modul); // Расшифровываем: encrypted_num^key_r mod modul
                unsigned char byte = static_cast<unsigned char>(decrypted); // Приводим результат к unsigned char (предполагается, что результат лежит в диапазоне 0..255; static_cast - преобразование типа
                out.put(byte); // out.put(byte) записывает один байт в выходной файл
            }
            in.close(); // закрываем input.txt, из которого читали исходные байты
            out.close(); // закрываем Shamir_encrypted.txt, в который записывали шифротекст
            cout << "Расшифрование завершено: Shamir_ncrypted.txt -> Shamir_decrypted.txt" << endl; // В итоге получаем исходный decrypted.txt, который должен совпадать с input.txt
        }
        break;
    }

    case 2: { // Шифр RSA
        int p, q, open_ex, close_ex;

        cout << "Введите простое число p: ";
        cin >> p;
        cout << "Введите простое число q: ";
        cin >> q;

        int modul = p * q;
        int phi = (p - 1) * (q - 1);
        cout << "Модуль (modul) = " << modul << endl;
        cout << "Функция Эйлера (phi) = " << phi << endl;

        cout << "Введите открытую экспоненту (open_ex): ";
        cin >> open_ex;
        cout << "Введите закрытую экспоненту (close_ex): ";
        cin >> close_ex;

        // Проверка согласованности ключей
        if ((open_ex * close_ex) % phi != 1) {
            cout << "Ошибка: open_ex * close_ex mod phi != 1. Шифр не сможет правильно расшифровать." << endl;
            break;
        }

        // Шифрование файла (открытым ключом open_ex)
        {
            ifstream in("input.txt", ios::binary); // Открываем исходный файл в бинарном режиме (ios::binary), чтобы читать байты без преобразований; ifstream - Используется для чтения данных из файла
            if (!in.is_open()) { // is_open() – проверка, открыт ли файл успешно, !in.is_open() возвращает true, если файл не открыт
                cout << "Ошибка: не удалось открыть input.txt" << endl;
                break;
            }
            ofstream out("RSA_encrypted.txt"); // ofstream - Используется для записи данных в файл
            if (!out.is_open()) { // is_open() – проверка, открыт ли файл успешно, !in.is_open() возвращает true, если файл не открыт
                cout << "Ошибка: не удалось создать RSA_encrypted.txt" << endl;
                break;
            }

            // Читаем файл побайтово. in.get(ch) извлекает очередной символ (байт) в переменную ch
            char ch;
            while (in.get(ch)) { 
                unsigned char byte = static_cast<unsigned char>(ch); // Преобразуем в unsigned char, чтобы значение байта было от 0 до 255; static_cast - преобразование типа
                int number_en = static_cast<int>(byte); // Приводим к int number_en – целое число, которое будем шифровать
                if (number_en >= modul) {
                    cout << "Ошибка: байт " << number_en << " >= modul " << modul << ". Невозможно зашифровать." << endl;
                    cout << "Увеличьте модуль (p*q > 255)." << endl;
                    in.close(); // закрываем input.txt, из которого читали исходные байты
                    out.close(); // закрываем RSA_encrypted.txt, в который записывали шифротекст
                    break;
                }
                int encrypted = modpow(number_en, open_ex, modul); // Вычисляем зашифрованное число: number_en^open_ex mod modul
                out << encrypted << endl; // Записываем его в файл encrypted.txt в виде десятичной строки, затем перевод строки
            }
            in.close(); // закрываем input.txt, из которого читали исходные байты
            out.close(); // закрываем RSA_encrypted.txt, в который записывали шифротекст
            cout << "Шифрование завершено: input.txt -> RSA_encrypted.txt" << endl;
        }

        //Расшифрование файла (закрытым ключом close_ex)
        {
            ifstream in("RSA_encrypted.txt"); // Открываем RSA_encrypted.txt для чтения чисел (текстовый режим); ifstream - Используется для чтения данных из файла
            if (!in.is_open()) { // is_open() – проверка, открыт ли файл успешно, !in.is_open() возвращает true, если файл не открыт
                cout << "Ошибка: не удалось открыть RSA_encrypted.txt" << endl;
                break;
            }
            ofstream out("RSA_decrypted.txt", ios::binary); // // ofstream - Используется для записи данных в файл
            if (!out.is_open()) { // is_open() – проверка, открыт ли файл успешно, !in.is_open() возвращает true, если файл не открыт
                cout << "Ошибка: не удалось создать RSA_decrypted.txt" << endl;
                break;
            }

            int encrypted_num;
            while (in >> encrypted_num) { // in >> encrypted_num читает очередное целое число из файла (останавливаясь на пробеле или переводе строки)
                int decrypted = modpow(encrypted_num, close_ex, modul); // Расшифровываем: encrypted_num^close_ex mod modul
                unsigned char byte = static_cast<unsigned char>(decrypted); // Приводим результат к unsigned char (предполагается, что результат лежит в диапазоне 0..255; static_cast - преобразование типа
                out.put(byte); // out.put(byte) записывает один байт в выходной файл
            }
            in.close(); // закрываем input.txt, из которого читали исходные байты
            out.close(); // закрываем RSA_encrypted.txt, в который записывали шифротекст
            cout << "Расшифрование завершено: RSA_encrypted.txt -> RSA_decrypted.txt" << endl;
        }
        break;
    }

    default:
        cout << "Неверный выбор. Используйте 1 или 2." << endl;
        break;
    }
    return 0;
}
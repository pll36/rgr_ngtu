#include <iostream>
#include <locale.h>

using namespace std;

// Функция для быстрого возведения в степень по модулю (base^exp % mod)
// Использует бинарный алгоритм (возведение в степень через разложение показателя на биты)
int modpow(int base, int exp, int mod) {
    int result = 1;          // здесь будет накапливаться результат
    base = base % mod;       // приводим основание к диапазону [0, mod-1]

    // Пока показатель степени не стал нулём
    while (exp > 0) {
        // Если текущий младший бит показателя равен 1, умножаем результат на base
        if (exp & 1) {
            result = (result * base) % mod;
        }
        // Возводим base в квадрат (переход к следующему биту)
        base = (base * base) % mod;
        // Сдвигаем биты показателя вправо (отбрасываем уже обработанный бит)
        exp >>= 1;
    }
    return result;
}

int main() {
    setlocale(LC_ALL, "ru");
    int choice;   // переменная для выбора режима (1 - Шамир, 2 - RSA)
    cout << "Выберите шифр:" << endl;
    cout << "1 - Шамира" << endl;
    cout << "2 - RSA" << endl;
    cin >> choice;

    // В зависимости от выбора выполняем нужный блок кода
    switch (choice) {
        // Шифр Шамира
    case 1: {
        // Переменные: modul - простое число(модуль),
        // key_sh - ключ шифрования, key_r - ключ расшифрования,
        // message - исходное сообщение (число)
        int modul, key_sh, key_r, message;

        cout << "Введите простое число для модуля (modul): ";
        cin >> modul;

        cout << "Введите ключ шифрования (key_sh): ";
        cin >> key_sh;

        cout << "Введите ключ расшифрования (key_r): ";
        cin >> key_r;

        // Ключи должны быть согласованы: key_sh * key_r ? 1 (mod modul-1)
        // Иначе расшифрование не восстановит исходное сообщение
        if ((key_sh * key_r) % (modul - 1) != 1) {
            cout << "Ошибка: key_sh * key_r mod (modul-1) != 1. Шифр не сможет правильно расшифровать." << endl;
            break;   // выходим из этого case, чтобы не выполнять шифрование с ошибкой
        }

        cout << "Введите исходное сообщение, целое число для шифрования (0 < message < " << modul << "): ";
        cin >> message;

        // Проверяем, что сообщение находится в допустимом диапазоне (не ноль и меньше modul)
        if (message <= 0 || message >= modul) {
            cout << "Число должно быть в диапазоне (0, " << modul << ")" << endl;
            break;
        }

        // Шифрование: encrypted = message^key_sh mod modul, encrypted - Зашифрованное сообщение
        int encrypted = modpow(message, key_sh, modul);
        cout << "Зашифрованное сообщение: " << encrypted << endl;

        // Расшифрование: расшифрованное = encrypted^key_r mod modul, decrypted - Расшифрованное сообщение
        int decrypted = modpow(encrypted, key_r, modul);
        cout << "Расшифрованное сообщение: " << decrypted << endl;

        // Проверяем, совпадает ли расшифрованное с исходным
        if (decrypted == message) {
            cout << "Расшифрование успешно!" << endl;
        }
        else {
            cout << "Ошибка расшифрования!" << endl;
        }
        break;   // конец case 1
    }
          // Шифр RSA
    case 2: {
        // Переменные: p и q - два простых числа,
        // open_ex - открытая экспонента, close_ex - закрытая экспонента,
        // message - исходное сообщение
        int p, q, open_ex, close_ex, message;

        cout << "Введите простое число (p): ";
        cin >> p;
        cout << "Введите простое число (q): ";
        cin >> q;

        // Вычисляем модуль modul = p * q и функцию Эйлера phi(?) = (p-1)*(q-1)
        int modul = p * q;
        int phi = (p - 1) * (q - 1);

        cout << "Модуль (modul) = " << modul << endl;
        cout << "Функция Эйлера (phi) = " << phi << endl;

        cout << "Введите открытую экспоненту (open_ex): ";
        cin >> open_ex;
        cout << "Введите закрытую экспоненту (close_ex): ";
        cin >> close_ex;

        // Для корректной работы RSA должно выполняться open_ex * close_ex ? 1 (mod ?)
        // Иначе расшифрование не восстановит сообщение
        if ((open_ex * close_ex) % phi != 1) {
            cout << "Ошибка: open_ex * close_ex mod phi != 1. Шифр не сможет правильно расшифровать." << endl;
            break;
        }

        cout << "Введите исходное сообщение, целое число для шифрования (0 < message < " << modul << "): ";
        cin >> message;

        // Сообщение должно быть строго между 0 и modul
        if (message <= 0 || message >= modul) {
            cout << "Число должно быть в диапазоне (0, " << modul << ")" << endl;
            break;
        }

        // Шифрование: encrypted = m^open_ex mod modul, encrypted - Зашифрованное сообщение 
        int encrypted = modpow(message, open_ex, modul);
        cout << "Зашифрованное сообщение: " << encrypted << endl;

        // Расшифрование: расшифрованное = encrypted^close_ex mod modul
        int decrypted = modpow(encrypted, close_ex, modul);
        cout << "Расшифрованное сообщение: " << decrypted << endl;

        // Проверка успешности расшифрования
        if (decrypted == message) {
            cout << "Расшифрование успешно!" << endl;
        }
        else {
            cout << "Ошибка расшифрования!" << endl;
        }
        break;   // конец case 2
    }

    default:
        // Если пользователь ввёл не 1 и не 2
        cout << "Неверный выбор. Используйте 1 или 2." << endl;
        break;
    }

    return 0;
}
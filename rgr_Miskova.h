#ifndef RGR_MISKOVA_H
#define RGR_MISKOVA_H
#include <string>

using namespace std;

// Ўифр Ўамира (степенной шифр)
// Ўифрует строку байтов алгоритмом Ўамира.
// modulus Ц простое число, должно быть > 255 дл€ шифровани€ всех байтов
// key_enc Ц экспонента шифровани€
// ¬озвращает шифротекст в виде дес€тичных чисел, разделЄнных переводом строки.
string encryptShamir(const string& plaintext, int modulus, int key_enc);

// –асшифровывает шифротекст Ўамира, полученный из encryptShamir.
// modulus Ц тот же простой модуль, что и при шифровании
// key_dec  Ц экспонента расшифровани€, должно выполн€тьс€ (key_enc * key_dec) % (modulus-1) == 1
// ¬озвращает исходный открытый текст.
string decryptShamir(const string& ciphertext, int modulus, int key_dec);

// Ўифр RSA
// Ўифрует строку байтов алгоритмом RSA.
// modulus Ц произведение двух простых чисел (p*q), должно быть > 255
// key_enc Ц открыта€ экспонента
// ¬озвращает шифротекст в виде дес€тичных чисел, разделЄнных переводом строки.
string encryptRSA(const string& plaintext, int modulus, int key_enc);

// –асшифровывает шифротекст RSA, полученный из encryptRSA.
// modulus Ц тот же модуль (p*q), что и при шифровании
// key_dec Ц закрыта€ экспонента, должно выполн€тьс€ (key_enc * key_dec) % ?(n) == 1
// ¬озвращает исходный открытый текст.
string decryptRSA(const string& ciphertext, int modulus, int key_dec);

#endif // RGR_MISKOVA_H
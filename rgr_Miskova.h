#ifndef RGR_MISKOVA_H
#define RGR_MISKOVA_H
#include <string>

using namespace std;


string encryptShamir(const string& plaintext, int modulus, int key_enc);

string decryptShamir(const string& ciphertext, int modulus, int key_dec);

string encryptRSA(const string& plaintext, int modulus, int key_enc);

string decryptRSA(const string& ciphertext, int modulus, int key_dec);

#endif

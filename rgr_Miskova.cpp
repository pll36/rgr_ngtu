#include "rgr_Miskova.h"
#include <sstream>
#include <stdexcept>
#include <string>

using namespace std;

// Modular exponentiation: (base^exp) % mod
static int modpow(int base, int exp, int mod) {
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

// Shamir cipher - encryption
string encryptShamir(const string& plaintext, int modulus, int key_enc) {
    if (modulus <= 0 || key_enc <= 0) {
        throw invalid_argument("Modulus and key must be positive");
    }

    string ciphertext;
    for (unsigned char ch : plaintext) {
        int byte_val = static_cast<int>(ch);
        if (byte_val >= modulus) {
            throw runtime_error("Byte value >= modulus. Increase modulus (must be > 255).");
        }
        int enc = modpow(byte_val, key_enc, modulus);
        ciphertext += to_string(enc) + "\n";
    }
    return ciphertext;
}

// Shamir cipher - decryption
string decryptShamir(const string& ciphertext, int modulus, int key_dec) {
    if (modulus <= 0 || key_dec <= 0) {
        throw invalid_argument("Modulus and key must be positive");
    }

    istringstream iss(ciphertext);
    string plaintext;
    string line;
    while (getline(iss, line)) {
        if (line.empty()) continue;
        int enc_num = stoi(line);
        int dec = modpow(enc_num, key_dec, modulus);
        plaintext.push_back(static_cast<char>(dec));
    }
    return plaintext;
}

// RSA cipher - encryption
string encryptRSA(const string& plaintext, int modulus, int key_enc) {
    if (modulus <= 0 || key_enc <= 0) {
        throw invalid_argument("Modulus and key must be positive");
    }

    string ciphertext;
    for (unsigned char ch : plaintext) {
        int byte_val = static_cast<int>(ch);
        if (byte_val >= modulus) {
            throw runtime_error("Byte value >= modulus. Increase modulus (p*q > 255).");
        }
        int enc = modpow(byte_val, key_enc, modulus);
        ciphertext += to_string(enc) + "\n";
    }
    return ciphertext;
}

// RSA cipher - decryption
string decryptRSA(const string& ciphertext, int modulus, int key_dec) {
    if (modulus <= 0 || key_dec <= 0) {
        throw invalid_argument("Modulus and key must be positive");
    }

    istringstream iss(ciphertext);
    string plaintext;
    string line;
    while (getline(iss, line)) {
        if (line.empty()) continue;
        int enc_num = stoi(line);
        int dec = modpow(enc_num, key_dec, modulus);
        plaintext.push_back(static_cast<char>(dec));
    }
    return plaintext;
}
#include <iostream>
#include <fstream>
#include <string>

#ifdef _WIN32
#define NOMINMAX
#include <windows.h>
#endif

#include "Kinstler_rgr.h"
#include "rgr_Rubtsov.h"
#include "rgr_Miskova.h"

// ============================================================
//  Helper functions
// ============================================================

static int readInt(const std::string& prompt, int lowerBound, int upperBound)
{
    int value;
    while (true)
    {
        std::cout << prompt;
        if (std::cin >> value)
        {
            if (value >= lowerBound && value <= upperBound)
                return value;
            std::cout << "Error: enter a number from " << lowerBound
                << " to " << upperBound << ".\n";
        }
        else
        {
            std::cout << "Error: integer expected. Try again.\n";
            std::cin.clear();
            std::cin.ignore(10000, '\n');
        }
    }
}

static std::string readWord(const std::string& prompt)
{
    std::string word;
    while (true)
    {
        std::cout << prompt;
        if (std::cin >> word && !word.empty())
            return word;
        std::cout << "Error: input must not be empty. Try again.\n";
        std::cin.clear();
        std::cin.ignore(10000, '\n');
    }
}

static bool readFile(const std::string& filename, std::string& content)
{
    std::ifstream file(filename, std::ios::binary);
    if (!file)
    {
        std::cout << "Error: cannot open file \"" << filename << "\".\n";
        return false;
    }
    content.assign(
        (std::istreambuf_iterator<char>(file)),
        std::istreambuf_iterator<char>());
    return true;
}

static void printResult(const std::string& original,
    const std::string& encrypted,
    const std::string& decrypted)
{
    std::cout << "\n===== Original text =====\n" << original << "\n";
    std::cout << "\n===== Encrypted text =====\n" << encrypted << "\n";
    std::cout << "\n===== Decrypted text =====\n" << decrypted << "\n";

    if (original == decrypted)
        std::cout << "\nCheck passed: texts match.\n";
    else
        std::cout << "\nWarning: decrypted text differs from original!\n";
}

// ============================================================
//  Egor Kinstler menu -- Columnar Transposition & TEA
// ============================================================

static void menuKinstler()
{
    while (true)
    {
        std::cout << "\n--- Maxim Kinstler ciphers ---\n"
            << "1 - Columnar Transposition\n"
            << "2 - TEA\n"
            << "0 - Back\n";

        int choice = readInt("Your choice: ", 0, 2);
        if (choice == 0) return;

        std::string filename, text;
        while (true)
        {
            filename = readWord("Enter file name: ");
            if (readFile(filename, text)) break;
        }

        std::string encrypted, decrypted;

        if (choice == 1)
        {
            std::string key = readWord("Enter key (word): ");
            encrypted = encryptColumnar(text, key);
            decrypted = decryptColumnar(encrypted, key);
        }
        else
        {
            TeaKey key = { { 0x12345678, 0x9ABCDEF0, 0x11223344, 0x55667788 } };
            encrypted = encryptTEA(text, key);
            decrypted = decryptTEA(encrypted, key);
        }

        printResult(text, encrypted, decrypted);
    }
}

// ============================================================
//  Maxim Rubtsov menu -- Affine cipher
// ============================================================

static void menuRubtsov()
{
    while (true)
    {
        std::cout << "\n--- Egor Rubtsov ciphers ---\n"
            << "1 - Affine cipher\n"
            << "0 - Back\n";

        int choice = readInt("Your choice: ", 0, 1);
        if (choice == 0) return;

        int a, b, modulus;
        std::cout << "Enter affine cipher parameters.\n";

        while (true)
        {
            modulus = readInt("  Modulus (e.g. 26 for Latin): ", 2, 1000000);
            a = readInt("  Coefficient a (must be coprime with modulus): ", 1, modulus - 1);
            b = readInt("  Coefficient b: ", 0, modulus - 1);

            AffineKey cipher;
            if (initializeAffineKey(cipher, a, b, modulus))
            {
                std::string filename, text;
                while (true)
                {
                    filename = readWord("Enter file name: ");
                    if (readFile(filename, text)) break;
                }

                std::string encrypted = encryptAffine(text, cipher);
                std::string decrypted = decryptAffine(encrypted, cipher);
                printResult(text, encrypted, decrypted);
                break;
            }
            else
            {
                std::cout << "Error: a and modulus are not coprime. Enter different parameters.\n";
            }
        }
    }
}

// ============================================================
//  Primality check helper
// ============================================================

static bool isPrime(int n)
{
    if (n < 2) return false;
    if (n == 2) return true;
    if (n % 2 == 0) return false;
    for (int i = 3; i * i <= n; i += 2)
        if (n % i == 0) return false;
    return true;
}

// ============================================================
//  Alina Miskova menu -- Shamir & RSA
// ============================================================

static void menuMiskova()
{
    while (true)
    {
        std::cout << "\n--- Alina Miskova ciphers ---\n"
            << "1 - Shamir cipher\n"
            << "2 - RSA\n"
            << "0 - Back\n";

        int choice = readInt("Your choice: ", 0, 2);
        if (choice == 0) return;

        std::string filename, text;
        while (true)
        {
            filename = readWord("Enter file name: ");
            if (readFile(filename, text)) break;
        }

        // Get two primes p and q, compute modulus = p*q > 255
        int p, q, modulus;
        while (true)
        {
            p = readInt("Enter prime number p: ", 2, 1000000);
            if (!isPrime(p))
            {
                std::cout << "Error: " << p << " is not prime. Try again.\n";
                continue;
            }
            q = readInt("Enter prime number q (p*q must be > 255): ", 2, 1000000);
            if (!isPrime(q))
            {
                std::cout << "Error: " << q << " is not prime. Try again.\n";
                continue;
            }
            modulus = p * q;
            if (modulus <= 255)
            {
                std::cout << "Error: p*q = " << modulus
                    << ", must be > 255. Choose larger primes.\n";
                continue;
            }
            std::cout << "Modulus n = p*q = " << modulus << "\n";
            break;
        }

        int keyEnc = readInt("Enter encryption key: ", 1, modulus - 1);
        int keyDec = readInt("Enter decryption key: ", 1, modulus - 1);

        try
        {
            std::string encrypted, decrypted;

            if (choice == 1)
            {
                encrypted = encryptShamir(text, modulus, keyEnc);
                decrypted = decryptShamir(encrypted, modulus, keyDec);
            }
            else
            {
                encrypted = encryptRSA(text, modulus, keyEnc);
                decrypted = decryptRSA(encrypted, modulus, keyDec);
            }

            printResult(text, encrypted, decrypted);
        }
        catch (const std::exception& ex)
        {
            std::cout << "Encryption error: " << ex.what() << "\n";
        }
    }
}

// ============================================================
//  Main menu
// ============================================================

int main()
{
#ifdef _WIN32
    SetConsoleOutputCP(65001);
    SetConsoleCP(65001);
#endif
    setlocale(LC_ALL, "");

    while (true)
    {
        std::cout << "\n========== Select team member ==========\n"
            << "1 - Maxim Kinstler   (Columnar Transposition, TEA)\n"
            << "2 - Egor Rubtsov   (Affine cipher)\n"
            << "3 - Alina Miskova   (Shamir, RSA)\n"
            << "0 - Exit\n";

        int member = readInt("Your choice: ", 0, 3);

        switch (member)
        {
        case 0:
            std::cout << "Goodbye!\n";
            return 0;
        case 1:
            menuKinstler();
            break;
        case 2:
            menuRubtsov();
            break;
        case 3:
            menuMiskova();
            break;
        }
    }
}
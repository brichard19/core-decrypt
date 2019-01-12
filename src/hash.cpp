#include <string>
#include <iostream>

#include "core-decrypt.h"

static const std::string alphabet = "abcdefghijklmnopqrstuvwxyz";

static int alphabet_size = (int)alphabet.length();

static unsigned int endian(unsigned int x)
{
    return (x << 24) | (x >> 24) | ((x & 0xff00) << 8) | ((x & 0xff0000) >> 8);
}

void password_kdf(const char *password, int len, unsigned int iterations, unsigned char *salt, unsigned int *hash)
{
    uint64_t state[8];

    uint64_t msg[16] = { 0 };

    // Encode password into the message
    int shift = 56;
    for(int i = 0; i < len; i++) {
        if(i >= 8 && i % 8 == 0) {
            shift = 56;
        }
        uint64_t c = (uint64_t)password[i];

        msg[i / 8] |= c << shift;
        shift -= 8;
    }

    // Encode salt
    for(int i = 0; i < 8; i++) {
        uint64_t b = salt[i];
        msg[(len + i)/8] |= b << ((7 - ((len + i) % 8))) * 8;
    }

    // Apply padding byte
    msg[(len + 8)/8] |= (uint64_t)0x80 << (7 - ((len + 8) % 8)) * 8;
    msg[15] = (len + 8) * 8;

 
    sha512_iterations(msg, state, iterations);

    hash[0] = (unsigned int)(state[0] >> 32);
    hash[1] = (unsigned int)state[0];

    hash[2] = (unsigned int)(state[1] >> 32);
    hash[3] = (unsigned int)state[1];

    hash[4] = (unsigned int)(state[2] >> 32);
    hash[5] = (unsigned int)state[2];

    hash[6] = (unsigned int)(state[3] >> 32);
    hash[7] = (unsigned int)state[3];
}

void next_password(char *password, int len, uint64_t count)
{
    for(int i = len - 1; i >= 0; i--) {
        int idx = count % alphabet_size;
        password[i] = alphabet[idx];
        count -= idx;
        count /= alphabet_size;
    }
}

bool test_key(unsigned int key[8], unsigned int encrypted_block[4], unsigned int iv[4])
{
    unsigned int pt[4];

    aes256_cbc_decrypt(key, iv, encrypted_block, pt);

    return pt[0] == 0x10101010 && pt[1] == 0x10101010 && pt[2] == 0x10101010 && pt[3] == 0x10101010;
}

bool brute_force(int password_len, unsigned int encrypted_block[4], unsigned int iv[4], unsigned char salt[8], unsigned int iterations, uint64_t start, uint64_t end, uint64_t stride)
{
    char password[12] = { 0 };
    unsigned int key[8];

    for(uint64_t i = start; i <= end; i+=stride) {
        next_password(password, password_len, i);

        password_kdf(password, password_len, iterations, salt, key);

        if(test_key(key, encrypted_block, iv)) {
            std::cout << "Found password!" << std::endl;
            std::cout << password << std::endl;
            return true;
        }
    }

    return false;
}
#ifndef _CORE_DECRYPT_H
#define _CORE_DECRYPT_H

#include <string>
#include <stdint.h>
#include <vector>
#include <CL/cl.h>

struct device_info {
    cl_device_id id;
    int logical_id;
    std::string name;
    unsigned int cores;
    unsigned int clock_frequency;
    uint64_t memory;
};

struct password_offset {
    unsigned int start;
    unsigned int count;
};

class PasswordDictionary {

private:
    std::vector<std::string> _files;
    std::vector<int> _format;

    std::string _dictionary;
    std::vector<unsigned int> _index;
    std::vector<struct password_offset> _offsets;

    void load();

public:
    PasswordDictionary(const std::vector<std::string> &password_files, const std::vector<int> format);

    uint64_t get_size();
    std::string get_password(uint64_t idx);

    std::string& get_words() {
        return _dictionary;
    };

    std::vector<unsigned int>& get_index() {
        return _index;
    }

    std::vector<struct password_offset> get_offsets()
    {
        return _offsets;
    }
};

void password_kdf(const char *password, int len, unsigned int iterations, unsigned char *salt, unsigned int *hash);

void sha512_init(uint64_t *state);
void sha512(const uint64_t *msg, uint64_t *state);

void aes256_cbc_decrypt(unsigned int key[8], unsigned int iv[4], unsigned int ciphertext[4], unsigned int plaintext[4]);
void sha512_iterations(uint64_t *msg, uint64_t *state, unsigned int iterations);
bool test_key(unsigned int key[8], unsigned int encrypted_block[4], unsigned int iv[4]);

bool brute_force(int password_len, unsigned int encrypted_block[4], unsigned int iv[4], unsigned char salt[8], unsigned int iterations, uint64_t start, uint64_t end, uint64_t stride);
bool brute_force_cl(int password_len, unsigned int encrypted_block[4], unsigned int iv[4], unsigned char salt[8], unsigned int iterations, uint64_t start, uint64_t end, uint64_t stride);
bool dictionary_cl(struct device_info &device, PasswordDictionary &dictionary, unsigned int encrypted_block[4], unsigned int iv[4], unsigned char salt[8], unsigned int iterations, uint64_t start, int stride, unsigned int intensity = 1000);
std::vector<struct device_info> get_devices();


#endif
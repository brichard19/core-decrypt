#include <iostream>
#include <cstring>
#include "core-decrypt.h"

std::vector<unsigned int> parse_words(std::string s)
{
    // Pad the beginning with 0's
    if(s.length() % 8 != 0) {
        int count = 8 - s.length() % 8;
        for(int i = 0; i < count; i++) {
            s = "0" + s;
        }
    }

    std::vector<unsigned int> words;

    for(int i = 0; i < s.length(); i+=8) {
        unsigned int word = 0;
        sscanf(s.substr(i, 8).c_str(), "%x", &word);
        words.push_back(word);
    }

    return words;
}

std::vector<unsigned char> parse_bytes(std::string s)
{
    // Pad the beginning with 0's
    if(s.length() % 2 != 0) {
        int count = 2 - s.length() % 2;
        for(int i = 0; i < count; i++) {
            s = "0" + s;
        }
    }

    std::vector<unsigned char> bytes;

    for(int i = 0; i < s.length(); i += 2) {
        unsigned int word = 0;
        sscanf(s.substr(i, 2).c_str(), "%x", &word);

        bytes.push_back((unsigned char)word);
    }

    return bytes;
}

bool is_hex(std::string &s)
{
    for(int i = 0; i < s.length(); i++) {
        char c = s[i];

        if(!(c >= '0' && c <= '9') && !(c >= 'a' && c <= 'f') && !(c >= 'A' && c <= 'F')) {
            return false;
        }
    }

    return true;
}


bool parse_encrypted_key(std::string s, unsigned int iv[4], unsigned int ct[4], unsigned char salt[8], unsigned int *iterations)
{
    if(s.length() != 88 || !is_hex(s)) {
        std::cout << "Invalid encrypted key: expected 88 hex characters" << std::endl;
        return false;
    }

    std::vector<unsigned int> words = parse_words(s.substr(0, 32));
    std::memcpy(iv, words.data(), 16);

    words = parse_words(s.substr(32, 32));
    std::memcpy(ct, words.data(), 16);

    std::vector<unsigned char> bytes = parse_bytes(s.substr(64, 16));
    std::memcpy(salt, bytes.data(), 8);

    words = parse_words(s.substr(80, 8));
    *iterations = words[0];

    return true;
}



void list_device(struct device_info &device)
{
    std::cout << "ID:         " << device.logical_id << std::endl;
    std::cout << "Name:       " << device.name << std::endl;
    std::cout << "Memory:     " << (device.memory / (1024 * 1024)) << "MB" << std::endl;
    std::cout << "Processors: " << device.cores << std::endl;
    std::cout << "Clock:      " << device.clock_frequency << "MHz" << std::endl;
}

void list_devices(std::vector<struct device_info> &devices)
{
    for(int i = 0; i < devices.size(); i++) {
        list_device(devices[i]);
        if(i < devices.size() - 1) {
            std::cout << std::endl;
        }
    }
}

bool parse_int(std::string s, int *x)
{
    if(sscanf(s.c_str(), "%d", x) != 1) {
        return false;
    }

    return true;
}

bool parse_uint64(std::string s, uint64_t *x)
{
    if(sscanf(s.c_str(), "%lld", x) != 1) {
        return false;
    }

    return true;
}

void parse_dictionaries(std::vector<std::string> input_files, std::vector<std::string> &files, std::vector<int> &format)
{
    files.clear();
    format.clear();

    // Construct a unique list
    for(int i = 0; i < input_files.size(); i++) {
        bool exists = false;

        for(int j = 0; j < files.size(); j++) {
            if(files[j] == input_files[i]) {
                exists = true;
                break;
            }
        }

        if(!exists) {
            files.push_back(input_files[i]);
        }
    }

    for(int i = 0; i < input_files.size(); i++) {
        for(int j = 0; j < files.size(); j++) {
            if(input_files[i] == files[j]) {
                format.push_back(j);
                break;
            }
        }
    }
}

void usage()
{
    std::cout << "btcdecrypt [OPTION] ENCRYPTED_KEY [WORD LISTS]" << std::endl;
    std::cout << std::endl;

    std::cout << "--list-devices          List available OpenCL devices" << std::endl;
    std::cout << "--device DEVICE         Specify OpenCL device to use" << std::endl;
    std::cout << "--start NUM             Specify where in the password space to start" << std::endl;
    std::cout << std::endl;
}

int main(int argc, char **argv)
{
    std::vector<std::string> args;
    for(int i = 1; i < argc; i++) {
        args.push_back(std::string(argv[i]));
    }

    int selected_device = 0;

    unsigned char salt[8];
    unsigned int ct[4];
    unsigned int iv[4];
    unsigned int iterations = 0;
    unsigned int intensity = 1000;
    uint64_t start = 0;

    std::vector<struct device_info> devices = get_devices();

    if(devices.size() == 0) {
        std::cout << "No OpenCL devices found" << std::endl;
        return 1;
    }

    // List devices and nothing else if '--list-devices' is used
    for(int i = 0; i < args.size(); i++) {
        if(args[i] == "--list-devices") {
            list_devices(devices);
            return 0;
        }
    }

    std::vector<std::string> operands;

    for(int i = 0; i < args.size(); i++) {
        std::string arg = args[i];
        std::string prefix = args[i] + ": ";
        bool arg_consumed = false;

        if(arg == "--device") {
            if(args.size() <= i + 1) {
                std::cout << prefix << "argument required" << std::endl;
                return 1;
            }
            if(!parse_int(args[i + 1], &selected_device)) {
                std::cout << prefix << "invalid argument" << std::endl;
                return 1;
            }

            if(selected_device >= devices.size()) {
                std::cout << "Invalid device ID" << std::endl;
                return 1;
            }

            arg_consumed = true;
        } else if(arg == "--start") {
            if(args.size() <= i + 1) {
                std::cout << prefix << "argument required" << std::endl;
                return 1;
            }

            if(!parse_uint64(args[i + 1], &start)) {
                std::cout << prefix << "invalid argument" << std::endl;
                return 1;
            }

            arg_consumed = true;
        } else {
            operands.push_back(args[i]);
        }

        if(arg_consumed) {
            i++;
        }
    }

    if(operands.size() == 0) {
        usage();
        return 1;
    }

    // First operand is encrypted key
    if(!parse_encrypted_key(operands[0], iv, ct, salt, &iterations)) {
        return 1;
    }

    if(operands.size() < 2) {
        std::cout << "Dictionary files required" << std::endl;
        return 1;
    }

    std::vector<std::string> dictionary_files;
    std::vector<int> format;

    std::vector<std::string> k(operands.begin() + 1, operands.end());
    parse_dictionaries(k, dictionary_files, format);

    std::cout << "Loading dictionary... ";
    PasswordDictionary d(dictionary_files, format);
    std::cout << "Done" << std::endl;

    std::cout << "Dictionary contains " << d.get_size() << " combinations" << std::endl;

    std::cout << "Selected device: " << devices[selected_device].name << std::endl;
    dictionary_cl(devices[selected_device], d, ct, iv, salt, iterations, start, 1);
}
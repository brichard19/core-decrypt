#include <fstream>
#include <sstream>

#include "util.h"
#include "core-decrypt.h"



PasswordDictionary::PasswordDictionary(const std::vector<std::string> &password_files, const std::vector<int> format)
{
    _files = password_files;
    _format = format;

    load();
}


void PasswordDictionary::load()
{
    unsigned int pos = 0;

    std::vector<struct password_offset> offsets;

    for(int i = 0; i < _files.size(); i++) {

        unsigned int start = (unsigned int)_index.size();

        std::ifstream inFile(_files[i].c_str());

        if(!inFile.is_open()) {
            return;
        }

        std::string line;

        while(std::getline(inFile, line)) {
            removeNewline(line);
            _index.push_back(pos);
            int len = (int)line.length();

            _dictionary += line;
            pos += len;
        }

        struct password_offset offset;
        offset.start = start;
        offset.count = (unsigned int)_index.size() - start;

        offsets.push_back(offset);

        // Add to the very end so the length of the last word (_index[i + 1] - _index[i]) can
        // still be calculated
        if(i == _files.size() - 1) {
            _index.push_back(pos);
        }
    }


    for(int i = 0; i < _format.size(); i++) {
        int idx = _format[i];

        _offsets.push_back(offsets[idx]);
    }
}

uint64_t PasswordDictionary::get_size()
{
    uint64_t size = 1;

    for(int i = 0; i < _offsets.size(); i++) {
        size *= _offsets[i].count;
    }

    return size;
}

std::string PasswordDictionary::get_password(uint64_t idx)
{
    std::string password;

    for(int col = 0; col < _offsets.size(); col++) {
        int start = _offsets[col].start;
        int word_index = idx % _offsets[col].count;

        int start_idx = _index[start + word_index];
        int len = _index[start + word_index + 1] - start_idx;

        password += _dictionary.substr(start_idx, len);

        idx -= word_index;
        idx /= _offsets[col].count;
    }

    return password;
}
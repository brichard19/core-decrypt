#include "util.h"


#ifdef _WIN32
#include <Windows.h>
#else
#include<stdio.h>
#include<sys/time.h>
#endif

uint64_t getSystemTime()
{
#ifdef _WIN32
    return GetTickCount64();
#else
    struct timeval t;
    gettimeofday(&t, NULL);
    return (uint64_t)t.tv_sec * 1000 + t.tv_usec / 1000;
#endif
}


void removeNewline(std::string &s)
{
    size_t len = s.length();

    int toRemove = 0;

    if(len >= 2) {
        if(s[len - 2] == '\r' || s[len - 2] == '\n') {
            toRemove++;
        }
    }
    if(len >= 1) {
        if(s[len - 1] == '\r' || s[len - 1] == '\n') {
            toRemove++;
        }
    }

    if(toRemove) {
        s.erase(len - toRemove);
    }
}
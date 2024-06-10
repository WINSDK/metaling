#include <cstdarg>
#include <cstdio>
#include <unistd.h>

void panic(const char * fmt, ...) {
    va_list args;
    va_start(args, fmt);
    vfprintf(stderr, fmt, args);
    va_end(args);
    _exit(1);
}

#include <cstdarg>
#include <cstdio>
#include <unistd.h>

void error(const char * fmt, ...) {
    va_list arglist;

    va_start(arglist, fmt);
    fprintf(stderr, "\033[1;31m" "error: " "\033[0m");
    vfprintf(stderr, fmt, arglist);
    va_end(arglist);

    _exit(1);
}

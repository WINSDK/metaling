#include <cstdarg>
#include <cstdio>
#include <unistd.h>
#include <Metal/Metal.hpp>

void error(const char * fmt, ...) {
    va_list arglist;

    va_start(arglist, fmt);
    fprintf(stderr, "\033[1;31m" "error: " "\033[0m");
    vfprintf(stderr, fmt, arglist);
    va_end(arglist);

    _exit(1);
}

void error_metal(NS::Error* err, const char * fmt, ...) {
    va_list arglist;

    va_start(arglist, fmt);
    fprintf(stderr, "\033[1;31m" "error: " "\033[0m");
    vfprintf(stderr, fmt, arglist);
    fprintf(stderr, ": %s", err->localizedDescription()->utf8String());
    va_end(arglist);

    _exit(1);
}

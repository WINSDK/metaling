#include <cstdarg>
#include <cstdio>
#include <unistd.h>
#include <Metal/Metal.hpp>

[[noreturn]] void error(const char * fmt, ...) {
    va_list arglist;

    va_start(arglist, fmt);
    fprintf(stderr, "\033[1;31m" "error: " "\033[0m" "\033[1m");
    vfprintf(stderr, fmt, arglist);
    fprintf(stderr, "\033[0m");
    va_end(arglist);

    _exit(1);
}

[[noreturn]] void error_metal(NS::Error* err, const char * fmt, ...) {
    va_list arglist;

    va_start(arglist, fmt);
    fprintf(stderr, "\033[1;31m" "error: " "\033[0m");
    vfprintf(stderr, fmt, arglist);
    if (err)
        fprintf(stderr, ":\n%s\n", err->localizedDescription()->utf8String());
    else
        fprintf(stderr, "\n");
    va_end(arglist);

    _exit(1);
}

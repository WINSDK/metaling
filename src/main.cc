#include <cassert>
#include <cstring>

#include "common.hpp"
#include "backend/cpu/cpu.hpp"
#include "backend/metal/metal.hpp"

namespace tests {
    void run();
}

// Assumption we make when casting strings.
static_assert(sizeof(char) == sizeof(u8));

const char* HELP = "failed to provide pattern, usage:\n"
                   "./metaling --test\n"
                   "           --help\n"
                   "           --backend cpu | metal\n"
                   "           {d|l|u|a|?}*";

int main(int argc, const char* argv[]) {
    if (argc < 2 || strcmp(argv[1], "--help") == 0)
        error("%s\n", HELP);

    if (strcmp(argv[1], "--test") == 0) {
        tests::run();
        return 0;
    }

    if (strcmp(argv[1], "--backend") == 0) {
        if (argc < 4)
            error("%s\n", HELP);

        const char* pattern = argv[3];

        if (strcmp(argv[2], "cpu") == 0)
            cpu::main(pattern);
        else if (strcmp(argv[2], "metal") == 0)
            metal::main(pattern);
        else
            error("unknown backend option '%s'\n", argv[2]);

    } else {
        const char* pattern = argv[1];

        // By default run the cpu backend.
        cpu::main(pattern);
    }

    return 0;
}

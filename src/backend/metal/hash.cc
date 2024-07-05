#include "src/backend/metal/hash.hpp"
#include "src/common.hpp"

namespace metal::hash {

const char DIGITS[] =
    R"(\0)"
    " "
    "0123456789";
const char LOWERCASE[] =
    R"(\0)"
    " "
    "abcdefghijklmnopqrstuvwxyz";
const char UPPERCASE[] =
    R"(\0)"
    " "
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
const char ALPHA[] =
    R"(\0)"
    " "
    "abcdefghijklmnopqrstuvwxyz"
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
const char ALPHA_NUM[] =
    R"(\0)"
    " "
    "0123456789"
    "abcdefghijklmnopqrstuvwxyz"
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
const char ANY[] =
    R"(\0)"
    " "
    "0123456789"
    "abcdefghijklmnopqrstuvwxyz"
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    R"(!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~)";

void generate_permutations(
    const char* pattern,
    u64 pattern_len,
    const char** char_sets,
    u32* set_sizes) {
    for (u64 idx = 0; idx < pattern_len; idx++) {
        switch (pattern[idx]) {
            case 'd':
                char_sets[idx] = DIGITS;
                set_sizes[idx] = sizeof(DIGITS);
                break;
            case 'l':
                char_sets[idx] = LOWERCASE;
                set_sizes[idx] = sizeof(LOWERCASE);
                break;
            case 'u':
                char_sets[idx] = UPPERCASE;
                set_sizes[idx] = sizeof(UPPERCASE);
                break;
            case 'a':
                char_sets[idx] = ALPHA;
                set_sizes[idx] = sizeof(ALPHA);
                break;
            case 'n':
                char_sets[idx] = ALPHA_NUM;
                set_sizes[idx] = sizeof(ALPHA_NUM);
                break;
            case '?':
                char_sets[idx] = ANY;
                set_sizes[idx] = sizeof(ANY);
                break;
            default:
                error("invalid pattern character '%c'\n", pattern[idx]);
        }
    }
}

} // namespace metal::hash

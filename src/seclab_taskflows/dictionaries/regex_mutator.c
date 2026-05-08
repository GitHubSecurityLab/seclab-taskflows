/* SPDX-FileCopyrightText: GitHub, Inc.
 * SPDX-License-Identifier: MIT
 *
 * Structure-aware libFuzzer/AFL++ custom mutator for regex pattern inputs.
 *
 * Heuristic input layout (suggested for harnesses):
 *   first byte    -> chooses syntax (oniguruma / pcre / posix)
 *   bytes 1-N     -> pattern + '\0' + subject
 *
 * The mutator splices regex meta-tokens and known-pathological
 * (catastrophic-backtracking) sub-patterns. It does NOT split on the '\0'
 * boundary deliberately: pattern compilers crash differently when the
 * subject bytes leak into the pattern, which is itself useful coverage.
 */

#include <stddef.h>
#include <stdint.h>
#include <string.h>

size_t LLVMFuzzerMutate(uint8_t *data, size_t size, size_t max_size);

static const char *kTokens[] = {
    /* Anchors, classes, quantifiers */
    "^", "$", "\\b", "\\B", "\\A", "\\z", "\\Z",
    ".", "\\d", "\\D", "\\w", "\\W", "\\s", "\\S",
    "*", "+", "?", "*?", "+?", "*+", "{3}", "{3,5}", "{1000000}",
    /* Groups */
    "(", ")", "(?:", "(?=", "(?!", "(?<=", "(?<!", "(?>",
    "(?P<n>", "(?<n>",
    /* Backreferences / recursion */
    "\\1", "\\g<n>", "(?R)", "(?1)",
    /* Character sets */
    "[", "]", "[^", "[a-z]", "[[:alpha:]]", "[:alnum:]",
    /* Alt / escapes */
    "|", "\\.", "\\\\",
    /* Modifiers */
    "(?i)", "(?m)", "(?s)", "(?x)", "(?-i)",
    /* Unicode / Property */
    "\\p{L}", "\\P{L}", "\\u0000", "\\xff",
    /* Pathological patterns (real ReDoS history) */
    "(a+)+", "(a|a)*", "((a*)*)*",
    "([a-zA-Z0-9])(([\\.\\-]?[a-zA-Z0-9]+)*)",
    "(a+)+@(a+)+",
};
#define NUM_TOKENS (sizeof(kTokens) / sizeof(kTokens[0]))

static uint32_t rnd(unsigned int *seed) {
    *seed = (*seed) * 1103515245u + 12345u;
    return *seed;
}

size_t LLVMFuzzerCustomMutator(uint8_t *data, size_t size,
                               size_t max_size, unsigned int seed) {
    if ((seed & 1u) == 0u) return LLVMFuzzerMutate(data, size, max_size);
    unsigned int r = seed;
    const char *tok = kTokens[rnd(&r) % NUM_TOKENS];
    size_t tlen = 0;
    while (tok[tlen]) tlen++;
    if (tlen == 0 || size + tlen > max_size) {
        return LLVMFuzzerMutate(data, size, max_size);
    }
    size_t off = (size == 0) ? 0 : (rnd(&r) % (size + 1u));
    memmove(data + off + tlen, data + off, size - off);
    memcpy(data + off, tok, tlen);
    return size + tlen;
}

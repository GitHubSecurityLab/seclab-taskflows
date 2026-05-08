/* SPDX-FileCopyrightText: GitHub, Inc.
 * SPDX-License-Identifier: MIT
 *
 * Structure-aware libFuzzer/AFL++ custom mutator for JSON-like inputs.
 *
 * Strategy: 50% of the time delegate to the engine's default byte mutator
 * (LLVMFuzzerMutate), 50% of the time perform one of a small set of JSON-
 * structural mutations:
 *
 *   - splice a token from a fixed dictionary at a random offset
 *   - flip the type of a JSON literal (true <-> false, 0 <-> "0", etc.)
 *   - duplicate a balanced bracket region
 *   - drop a balanced bracket region
 *
 * This dramatically improves coverage on JSON parsers that gate behaviour
 * on token kind (e.g. number vs. string vs. object), where pure byte-level
 * mutations almost never produce structurally-valid token transitions.
 *
 * Build alongside the harness:
 *   afl-clang-lto -fsanitize=fuzzer-no-link \
 *     harness.c json_mutator.c <library>.a -o harness.afl
 *
 * For libFuzzer:
 *   clang -fsanitize=fuzzer harness.c json_mutator.c <lib>.a -o harness.lf
 */

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

/* libFuzzer-provided default byte mutator. We call it for half the
 * iterations so we don't completely lose the engine's randomisation.
 * AFL++ via libAFLDriver re-exports the same symbol. */
size_t LLVMFuzzerMutate(uint8_t *data, size_t size, size_t max_size);

/* A small dictionary of high-leverage JSON tokens. The mutator picks one at
 * random and splices it in. */
static const char *kTokens[] = {
    "{}", "[]", "\"\"", "null", "true", "false",
    "{\"a\":1}", "[1,2,3]",
    "0", "-0", "1e308", "9007199254740992",
    "\\u0000", "\\uD800\\uDC00", "\\\"", "\\\\",
    ":", ",", "\"a\":", "\"id\":", "\"type\":",
};
#define NUM_TOKENS (sizeof(kTokens) / sizeof(kTokens[0]))

static uint32_t rnd(unsigned int *seed) {
    *seed = (*seed) * 1103515245u + 12345u;
    return *seed;
}

/* Find a balanced ()/[]/{} region starting at `start`. Returns the index of
 * the matching close, or 0 if no match. */
static size_t balanced_close(const uint8_t *data, size_t size, size_t start) {
    if (start >= size) return 0;
    char open = (char)data[start];
    char close;
    switch (open) {
        case '{': close = '}'; break;
        case '[': close = ']'; break;
        default: return 0;
    }
    int depth = 1;
    for (size_t i = start + 1; i < size; i++) {
        if ((char)data[i] == open) depth++;
        else if ((char)data[i] == close) {
            depth--;
            if (depth == 0) return i;
        }
    }
    return 0;
}

size_t LLVMFuzzerCustomMutator(uint8_t *data, size_t size,
                               size_t max_size, unsigned int seed) {
    /* 50% of the time, leave it to the engine. */
    if ((seed & 1u) == 0u) {
        return LLVMFuzzerMutate(data, size, max_size);
    }

    unsigned int r = seed;
    int op = (int)(rnd(&r) % 4u);

    switch (op) {
    case 0: {
        /* Splice a dictionary token. */
        const char *tok = kTokens[rnd(&r) % NUM_TOKENS];
        size_t tlen = strlen(tok);
        if (tlen == 0 || size + tlen > max_size) {
            return LLVMFuzzerMutate(data, size, max_size);
        }
        size_t off = (size == 0) ? 0 : (rnd(&r) % (size + 1u));
        memmove(data + off + tlen, data + off, size - off);
        memcpy(data + off, tok, tlen);
        return size + tlen;
    }
    case 1: {
        /* Type-flip: replace one of: true<->false, "..."" <->number, etc. */
        if (size < 4) return LLVMFuzzerMutate(data, size, max_size);
        size_t off = rnd(&r) % (size - 3u);
        if (memcmp(data + off, "true", 4) == 0 && off + 5 <= max_size) {
            memmove(data + off + 5, data + off + 4, size - off - 4);
            memcpy(data + off, "false", 5);
            return size + 1;
        }
        if (memcmp(data + off, "false", 5) == 0 && off + 5 <= size) {
            memcpy(data + off, "true ", 5); /* keep size */
            return size;
        }
        if (memcmp(data + off, "null", 4) == 0) {
            memcpy(data + off, "true", 4);
            return size;
        }
        if (data[off] == '"' && off + 2 < size) {
            /* Open quote -> drop it (splits a string). */
            memmove(data + off, data + off + 1, size - off - 1);
            return size - 1;
        }
        return LLVMFuzzerMutate(data, size, max_size);
    }
    case 2: {
        /* Duplicate a balanced region. */
        if (size < 2) return LLVMFuzzerMutate(data, size, max_size);
        size_t start = rnd(&r) % size;
        size_t close = balanced_close(data, size, start);
        if (close == 0) return LLVMFuzzerMutate(data, size, max_size);
        size_t span = close - start + 1;
        if (size + span > max_size) return LLVMFuzzerMutate(data, size, max_size);
        memmove(data + close + 1 + span, data + close + 1, size - close - 1);
        memcpy(data + close + 1, data + start, span);
        return size + span;
    }
    case 3: {
        /* Drop a balanced region. */
        if (size < 2) return LLVMFuzzerMutate(data, size, max_size);
        size_t start = rnd(&r) % size;
        size_t close = balanced_close(data, size, start);
        if (close == 0) return LLVMFuzzerMutate(data, size, max_size);
        size_t span = close - start + 1;
        memmove(data + start, data + close + 1, size - close - 1);
        return size - span;
    }
    }
    return LLVMFuzzerMutate(data, size, max_size);
}

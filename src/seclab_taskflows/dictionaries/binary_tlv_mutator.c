/* SPDX-FileCopyrightText: GitHub, Inc.
 * SPDX-License-Identifier: MIT
 *
 * Structure-aware libFuzzer/AFL++ custom mutator for length-prefixed binary
 * formats (PNG chunks, ELF sections, MP4 boxes, network protocols, etc).
 *
 * Input layout assumed: a sequence of records, each `<u32_be length><bytes>`.
 * Mutations:
 *   - rewrite a record's length to length+/-1 / 0 / 0xffffffff (catches
 *     integer-overflow, off-by-one, sign errors)
 *   - duplicate a record
 *   - drop a record
 *
 * Falls back to engine default for non-record-shaped inputs.
 */

#include <stddef.h>
#include <stdint.h>
#include <string.h>

size_t LLVMFuzzerMutate(uint8_t *data, size_t size, size_t max_size);

static uint32_t read_be32(const uint8_t *p) {
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8)  | (uint32_t)p[3];
}

static void write_be32(uint8_t *p, uint32_t v) {
    p[0] = (uint8_t)(v >> 24);
    p[1] = (uint8_t)(v >> 16);
    p[2] = (uint8_t)(v >> 8);
    p[3] = (uint8_t)v;
}

static uint32_t rnd(unsigned int *seed) {
    *seed = (*seed) * 1103515245u + 12345u;
    return *seed;
}

/* Walk records, return the offset of a randomly-chosen record header
 * (length field). 0 if none found. */
static size_t pick_record(const uint8_t *data, size_t size, unsigned int *r) {
    size_t off = 0;
    size_t starts[64];
    int nstarts = 0;
    while (off + 4 <= size && nstarts < 64) {
        starts[nstarts++] = off;
        uint32_t len = read_be32(data + off);
        if (len > size - off - 4) break; /* malformed; stop here */
        off += 4 + len;
    }
    if (nstarts == 0) return (size_t)-1;
    return starts[rnd(r) % (uint32_t)nstarts];
}

size_t LLVMFuzzerCustomMutator(uint8_t *data, size_t size,
                               size_t max_size, unsigned int seed) {
    if ((seed & 1u) == 0u) return LLVMFuzzerMutate(data, size, max_size);
    unsigned int r = seed;
    size_t rec = pick_record(data, size, &r);
    if (rec == (size_t)-1 || rec + 4 > size) {
        return LLVMFuzzerMutate(data, size, max_size);
    }

    int op = (int)(rnd(&r) % 3u);
    switch (op) {
    case 0: {
        /* Length-overflow attack. */
        static const uint32_t evil[] = {0u, 1u, 0xffffffffu, 0x7fffffffu, 0x80000000u};
        write_be32(data + rec, evil[rnd(&r) % (sizeof(evil)/sizeof(evil[0]))]);
        return size;
    }
    case 1: {
        /* Duplicate the record. */
        uint32_t len = read_be32(data + rec);
        size_t span = 4u + len;
        if (rec + span > size || size + span > max_size) {
            return LLVMFuzzerMutate(data, size, max_size);
        }
        memmove(data + rec + span + span, data + rec + span, size - rec - span);
        memcpy(data + rec + span, data + rec, span);
        return size + span;
    }
    case 2: {
        /* Drop the record. */
        uint32_t len = read_be32(data + rec);
        size_t span = 4u + len;
        if (rec + span > size) return LLVMFuzzerMutate(data, size, max_size);
        memmove(data + rec, data + rec + span, size - rec - span);
        return size - span;
    }
    }
    return LLVMFuzzerMutate(data, size, max_size);
}

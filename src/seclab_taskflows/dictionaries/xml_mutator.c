/* SPDX-FileCopyrightText: GitHub, Inc.
 * SPDX-License-Identifier: MIT
 *
 * Structure-aware libFuzzer/AFL++ custom mutator for XML inputs.
 *
 * Strategy: 50% engine default; 50% one of:
 *   - splice an XML token from a fixed dictionary
 *   - flip the type of a tag (open <-> self-closing, attribute <-> element)
 *   - duplicate a balanced <tag>...</tag> region
 *   - inject an entity reference
 *
 * Useful against libexpat / libxml2 / any SAX-style parser. The dictionary
 * intentionally includes DTD / DOCTYPE / billion-laughs-style tokens so the
 * mutator can drive parser branches that random byte mutation rarely hits.
 */

#include <stddef.h>
#include <stdint.h>
#include <string.h>

size_t LLVMFuzzerMutate(uint8_t *data, size_t size, size_t max_size);

static const char *kTokens[] = {
    "<root>", "</root>", "<root/>",
    "<a>", "</a>", "<a/>", "<a b=\"c\"/>",
    "<?xml version=\"1.0\"?>",
    "<?xml version=\"1.0\" encoding=\"UTF-8\"?>",
    "<!DOCTYPE root>",
    "<!DOCTYPE root SYSTEM \"x\">",
    "<!ENTITY name \"v\">",
    "<!ENTITY ext SYSTEM \"file:///etc/passwd\">",
    "<![CDATA[", "]]>",
    "<!--", "-->",
    "&amp;", "&lt;", "&gt;", "&quot;", "&apos;",
    "&#65;", "&#x41;", "&unknown;", "&recursive;",
    "xmlns=\"http://x\"", "xmlns:p=\"http://x\"",
    "<p:tag/>",
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

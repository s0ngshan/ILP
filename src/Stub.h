#ifndef ILP_STUB_H
#define ILP_STUB_H

#include <stdint.h>

#define STUB_JUMP_SIZE 5

/* output 必须指向至少 5 字节的可写缓冲区 */
void stub_make_jump(
    unsigned char *output,
    uint32_t stub_rva,
    uint32_t original_entry_rva
);

#endif
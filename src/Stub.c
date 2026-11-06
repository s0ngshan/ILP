#include "Stub.h"

void stub_make_jump(
    unsigned char *output,
    uint32_t stub_rva,
    uint32_t original_entry_rva
)
{
    /*
     * 使用无符号运算保留 32 位位移的编码，
     * 包括向低地址跳转时的补码表示。
     */
    uint32_t displacement =
        original_entry_rva - (stub_rva + STUB_JUMP_SIZE);

    output[0] = 0xE9;

    /* x86 使用小端序：低位字节在前 */
    output[1] = (unsigned char)(displacement);
    output[2] = (unsigned char)(displacement >> 8);
    output[3] = (unsigned char)(displacement >> 16);
    output[4] = (unsigned char)(displacement >> 24);
}
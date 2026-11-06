#include "Compress.h"
#include <stdlib.h>

int rle_compress(
    const unsigned char *input,
    size_t input_size,
    unsigned char *output,
    size_t output_capacity,
    size_t *output_size){
    // 检查输入是否为空指针
    if (output_size == NULL){
        return EXIT_FAILURE;
    }

    *output_size = 0;

    if (input_size == 0){
        return EXIT_SUCCESS;
    }

    if (input == NULL || output == NULL){
        return EXIT_FAILURE;
    }

    unsigned char current = 0;
    unsigned int count = 0;
    size_t written = 0;

    // 遍历每个字节
    for (size_t i = 0; i < input_size; i++){
        // 先处理高半字节，再处理低半字节
        for (unsigned int half = 0; half < 2; half++){
            unsigned char value;

            if (half == 0){
                value = (input[i] >> 4) & 0x0F; // 高半字节
            } else {
                value = input[i] & 0x0F;        // 低半字节
            }

            if (count == 0){
                current = value;
                count = 1;
            } else if (value == current && count < 16){
                count++;
            } else{
                if (written >= output_capacity){
                    return EXIT_FAILURE;        // 输出缓冲区不足
                }

                output[written++] = (unsigned char)((count -1) << 4) | current;

                current = value;
                count = 1;
            }
        }
    }

    if (count != 0){
        if (written >= output_capacity){
            return EXIT_FAILURE;            
        }

        output[written++] = (unsigned char)((count - 1) << 4) | current;
    }

    *output_size = written;
    return EXIT_SUCCESS;
}

int rle_decompress(
    const unsigned char *input,
    size_t input_size,
    unsigned char *output,
    size_t output_capacity,
    size_t *output_size
)
{
    if (output_size == NULL) {
        return EXIT_FAILURE;
    }

    *output_size = 0;

    if (input_size == 0) {
        return EXIT_SUCCESS;
    }

    if (input == NULL || output == NULL) {
        return EXIT_FAILURE;
    }

    size_t written = 0;

    unsigned char high = 0;
    int has_high = 0;  // 是否已经收到了一个高半字节

    for (size_t i = 0; i < input_size; ++i) {
        unsigned int count =
            ((unsigned int)input[i] >> 4) + 1;

        unsigned char value =
            (unsigned char)(input[i] & 0x0F);

        for (unsigned int j = 0; j < count; ++j) {
            if (!has_high) {
                /* 第一个半字节：先保存到高四位 */
                high = (unsigned char)(value << 4);
                has_high = 1;
            } else {
                /* 第二个半字节：拼成完整字节 */
                if (written >= output_capacity) {
                    return EXIT_FAILURE;
                }

                output[written++] =
                    (unsigned char)(high | value);

                has_high = 0;
            }
        }
    }

    /* 原始数据以字节为单位，不应该剩下半个字节 */
    if (has_high) {
        return EXIT_FAILURE;
    }

    *output_size = written;
    return EXIT_SUCCESS;
}
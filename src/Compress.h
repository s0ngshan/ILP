#ifndef ILP_COMPRESS_H
#define ILP_COMPRESS_H

#include <stddef.h> 

int rle_compress(
    const unsigned char *input,
    size_t input_size,
    unsigned char *output,
    size_t output_capacity,
    size_t *output_size
);

int rle_decompress(
    const unsigned char *input,
    size_t input_size,
    unsigned char *output,
    size_t output_capacity,
    size_t *output_size
);

#endif
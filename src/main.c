#include <stdio.h>
#include <stdlib.h>
#include "PE_Reader.h"

int main(int argc, char *argv[]) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <input.exe>\n",argv[0]);
        return EXIT_FAILURE;
    }

    const char *input_path = argv[1];

    printf("Input: %s\n",input_path);

    return EXIT_SUCCESS;
}
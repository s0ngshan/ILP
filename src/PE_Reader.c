#include "PE_Reader.h"
#include <stdio.h>
#include <stdlib.h>

// 读取
int pe_read_file(const char *path,PE_File *file){
    FILE *fp = fopen(path,"rb");
    if (!fp) {
        fprintf(stderr,"Fail to open file: %s\n",path);
        return EXIT_FAILURE;
    }

    if (fseek(fp,0,SEEK_END) != 0){
        fprintf(stderr,"Fail to seek file: %s\n",path);
        fclose(fp);
        return EXIT_FAILURE;
    }
    long size = ftell(fp);

    if (size <= 0) {
        fprintf(stderr,"Fail to get file size: %s\n",path);
        fclose(fp);
        return EXIT_FAILURE;
    }

    if (fseek(fp,0,SEEK_SET) != 0){
        fprintf(stderr,"Fail to seek file: %s\n",path);
        fclose(fp);
        return EXIT_FAILURE;
    }

    size_t file_size = (size_t)size;
    unsigned char *buffer = (unsigned char *)malloc(file_size);
    if (!buffer){
        fprintf(stderr,"Fail to allocate memory for file: %s\n",path);
        fclose(fp);
        return EXIT_FAILURE;
    }

    size_t bytes_read = fread(buffer,1,file_size,fp);
    fclose(fp);

    if (bytes_read != file_size){
        fprintf(stderr,"Fail to read complete file: %s\n",path);
        free(buffer);
        return EXIT_FAILURE;
    }
    
    file->data = buffer;
    file->size = file_size;

    return EXIT_SUCCESS;
}

// 释放内存
void pe_free_file(PE_File *file){
    if (file == NULL){
        return;
    }

    free(file->data);
    file->data = NULL;
    file->size = 0;
}

// PE验证
int pe_print_info(const PE_File *file){
    
}
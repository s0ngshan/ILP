#include "PE_Reader.h"
#include <stdio.h>
#include <stdlib.h>
#include <windows.h>
#include <string.h>

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
    if (file == NULL || 
        file->data == NULL){
        fprintf(stderr,"Invalid file buffer\n");
        return EXIT_FAILURE;
    }

    // 长度检查,至少保证大于64字节的DOS头结构体
    if (file->size < sizeof(IMAGE_DOS_HEADER)){
        fprintf(stderr,"FILE too small for DOS header\n");
        return EXIT_FAILURE;
    }

    IMAGE_DOS_HEADER dos;
    memcpy(&dos,file->data,sizeof(dos));

    // DOS头签名检查
    if (dos.e_magic != IMAGE_DOS_SIGNATURE){
        fprintf(stderr,"Invalid MZ signature\n");
        return EXIT_FAILURE;
    }

    printf("e_lfanew:0x%lx\n",(unsigned long)dos.e_lfanew);

    if (dos.e_lfanew < (LONG)sizeof(IMAGE_DOS_HEADER)){
        fprintf(stderr,"Invalid PE header offset\n");
        return EXIT_FAILURE;
    }

    size_t pe_offset = (size_t)dos.e_lfanew;

    if (pe_offset > file->size ||
        sizeof(DWORD) > file->size - pe_offset){
        fprintf(stderr,"PE signature outside file\n");
        return EXIT_FAILURE;
    }

    // 从偏移中复制出签名并做检验
    DWORD signature;
    memcpy(&signature,file->data + pe_offset,sizeof(signature));

    if (signature != IMAGE_NT_SIGNATURE){
        fprintf(stderr,"Invalid PE signature\n");
        return EXIT_FAILURE;
    }

    size_t file_header_offset = pe_offset + sizeof(signature);

    // 确认文件头
    if (file_header_offset > file->size ||
        sizeof(IMAGE_FILE_HEADER) > file->size - file_header_offset){
        fprintf(stderr,"File header outside file\n");
        return EXIT_FAILURE;
    }

    // 复制文件头
    IMAGE_FILE_HEADER file_header;
    memcpy(&file_header,file->data + file_header_offset,sizeof(file_header));

    // WORD转为unsigned int与打印格式匹配
    printf("Machine:0x%04x\n",(unsigned int)file_header.Machine);
    printf("NumberOfSections:%u\n",(unsigned int)file_header.NumberOfSections);
    printf("SizeOfOptionalHeader:%u\n",(unsigned int)file_header.SizeOfOptionalHeader);

    // 第一版只支持x86架构
    if (file_header.Machine != IMAGE_FILE_MACHINE_I386){
        fprintf(stderr,"Unsupported architecture: only x86 is supported\n");
        return EXIT_FAILURE;
    }

    size_t optional_header_offset = file_header_offset + sizeof(file_header);
    size_t optional_header_size = (size_t)file_header.SizeOfOptionalHeader;
    
    // 确认可选头
    if (optional_header_offset > file->size ||
        optional_header_size > file->size - optional_header_offset){
        fprintf(stderr,"Optional header outside file\n");
        return EXIT_FAILURE;
    }

    // 至少容纳标准PE32结构体
    if (optional_header_size < sizeof(IMAGE_OPTIONAL_HEADER32)){
        fprintf(stderr,"Unsupported optional header: expected PE32\n");
        return EXIT_FAILURE;
    }

    // 复制可选头
    IMAGE_OPTIONAL_HEADER32 optional_header;
    memcpy(&optional_header,file->data + optional_header_offset,sizeof(optional_header));

    // 确认PE32标识
    if (optional_header.Magic != IMAGE_NT_OPTIONAL_HDR32_MAGIC){
        fprintf(stderr,"Unsupported optional header: expected PE32\n");
        return EXIT_FAILURE;
    }

    printf("Entry RVA:0x%lx\n",(unsigned long)optional_header.AddressOfEntryPoint);
    printf("ImageBase:0x%lx\n",(unsigned long)optional_header.ImageBase);
    printf("SectionAlignment:0x%lx\n",(unsigned long)optional_header.SectionAlignment);      // 节的对齐粒度
    printf("FileAlignment:0x%lx\n",(unsigned long)optional_header.FileAlignment);            // 文件的对齐粒度
    printf("SizeOfImage:0x%lx\n",(unsigned long)optional_header.SizeOfImage);             

    // 读取验证节表，为后续压缩做准备
    size_t section_table_offset = optional_header_offset + optional_header_size;
    size_t section_count = (size_t)file_header.NumberOfSections;

    if (section_count == 0){
        fprintf(stderr,"No sections found\n");
        return EXIT_FAILURE;
    }

    if (section_table_offset > file->size ||
        section_count > (file->size - section_table_offset) / sizeof(IMAGE_SECTION_HEADER)){
        fprintf(stderr,"Section table outside file\n");
        return EXIT_FAILURE;
    }

    // 遍历节表，复制并打印节头
    for (size_t i = 0;i < section_count;i++){
        IMAGE_SECTION_HEADER section;
        
        size_t offset = section_table_offset + i * sizeof(section);
        memcpy(&section,file->data + offset,sizeof(section));

        printf("\nSection %zu:%.8s\n",i + 1,(const char *)section.Name);
        printf("VirtualAddress:0x%lx\n",(unsigned long)section.VirtualAddress);
        printf("VirtualSize:0x%lx\n",(unsigned long)section.Misc.VirtualSize);
        printf("PointerToRawData:0x%lx\n",(unsigned long)section.PointerToRawData);
        printf("SizeOfRawData:0x%lx\n",(unsigned long)section.SizeOfRawData);
        printf("Characteristics:0x%lx\n",(unsigned long)section.Characteristics);

        size_t raw_offset = (size_t)section.PointerToRawData;
        size_t raw_size = (size_t)section.SizeOfRawData;

        if (raw_size != 0){
            if (raw_offset > file->size ||
                raw_size > file->size - raw_offset){
                fprintf(stderr,"Section %zu raw data outside file\n",i + 1);
                return EXIT_FAILURE;
            }
        }
    }

    return EXIT_SUCCESS;
}
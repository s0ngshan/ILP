
typedef struct {
    unsigned char *data;
    size_t size;
} PE_File;

int pe_read_file(const char *path, PE_File *file);            // 文件读入内存，记录数据指针及文件大小
int pe_print_info(const PE_File *file);                       // 验证PE，打印基本信息
void pe_free_file(PE_File *file);                             // 释放内存

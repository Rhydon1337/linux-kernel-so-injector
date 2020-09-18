#include "elf.h"

#include <linux/limits.h>

#include "utils.h"
#include "consts.h"

int get_dynamic_section(struct task_struct* task, unsigned long number_of_entries, unsigned long module_base_address,
 unsigned long offset, unsigned long* dynamic_tables) {
    ssize_t result;
    Elf64_Phdr elf_section;
    size_t i;
    for (i = 0; i < number_of_entries; i++) {
        result = mem_read(task, (char*)&elf_section, sizeof(Elf64_Phdr), offset + (sizeof(Elf64_Phdr) * i));
        if (sizeof(Elf64_Phdr) != result) {
            return GET_DYNAMIC_SECTION_FAILED;
        }
        if (PT_DYNAMIC == elf_section.p_type) {
            *dynamic_tables = module_base_address + elf_section.p_vaddr;
            return SUCCESS;
        }
    }
    return GET_DYNAMIC_SECTION_FAILED;
}

void* get_dynamic_table(struct task_struct* task, size_t table_index, unsigned long dynamic_tables){
    Elf64_Dyn dynamic_table;
    ssize_t result;
    size_t i = 0;
    while (true) {
        result = mem_read(task, (char*)&dynamic_table, sizeof(Elf64_Dyn), dynamic_tables + (sizeof(Elf64_Dyn) * i));
        if (sizeof(Elf64_Dyn) != result) {
            return NULL;
        }
        if (table_index == dynamic_table.d_tag) {
            return (void*)dynamic_table.d_un.d_ptr;
        }
        ++i;
    }
    return NULL;
}

void* find_symbol(struct task_struct* task, unsigned long symbol_string_table, unsigned long symbol_table, const char* symbol_name) {
    Elf64_Sym symbol;
    ssize_t result;
    size_t i = 0;
    char found_symbol_name[MAX_SYMBOL_NAME] = { 0 };
    size_t symbol_len = strlen(symbol_name);
    while (true) {
        result = mem_read(task, (char*)&symbol, sizeof(Elf64_Sym), symbol_table + (sizeof(Elf64_Sym) * i));
        if (sizeof(Elf64_Sym) != result) {
            return NULL;
        } 
        result = mem_read(task, found_symbol_name, symbol_len, symbol_string_table + symbol.st_name);
        if (symbol_len != result) {
            return NULL;
        }
        if (0 == strncmp(symbol_name, found_symbol_name, symbol_len)) {
            return (void*)symbol.st_value;
        }
        ++i;
        memset(found_symbol_name, 0, MAX_SYMBOL_NAME);
    }
    return NULL;
}

void* get_symbol_address(struct task_struct* task, void* module_base_address, const char* symbol_name) {
    Elf64_Ehdr elf_header;
    unsigned long dynamic_tables;
    unsigned long symbol_string_table;
    unsigned long symbol_table;
    void* symbol_address;
    ssize_t result;
    unsigned long offset = (unsigned long)module_base_address;

    result = mem_read(task, (char*)&elf_header, sizeof(Elf64_Ehdr), offset);
    if (sizeof(Elf64_Ehdr) != result) {
        return NULL;
    }
    offset += elf_header.e_phoff;
    result = get_dynamic_section(task, elf_header.e_phnum, (unsigned long)module_base_address, offset, &dynamic_tables);
    if (SUCCESS != result) {
        return NULL;
    }
    
    symbol_string_table = (unsigned long)get_dynamic_table(task, DT_STRTAB, dynamic_tables);
    symbol_table = (unsigned long)get_dynamic_table(task, DT_SYMTAB, dynamic_tables);

    if (NULL == (void*)symbol_table || NULL == (void*)symbol_string_table) {
        return NULL;
    }
    symbol_address = find_symbol(task, symbol_string_table, symbol_table, symbol_name);
    if (NULL == symbol_address) {
        return NULL;
    }
    return symbol_address + (unsigned long)module_base_address;
}
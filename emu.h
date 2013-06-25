
#ifndef EMU_H
#define EMU_H

#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include "elf.h"

typedef struct {

	FILE *fd;
	int is_x64;
	union { 
		Elf32_Ehdr v32;
		Elf64_Ehdr v64;
	} elf_header;

	void *elf_sec; // Sections
	char *elf_str; // Sections String table
	void *elf_phr; // Program header entries
	char *elf_strtab; // Symbols string table
	void *elf_symtab; // Symbols table

} Program;


int emu_open_file(Program *p, char *filename);
void emu_free(Program *p);
int emu_verify_elf(Program *p);
int emu_sec_header(Program *p);
int emu_str_table(Program *p);
int emu_program_header(Program *p);
int emu_load_strtable(Program *p);
int emu_load_symbols(Program *p);

#endif
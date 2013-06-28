
#ifndef EMU_H
#define EMU_H

#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include "elf.h"

typedef struct {
	char opcode;
	
} Opcode;

enum { RAX, RCX, RDX, RBX, RSP, RBP, __NUM_REGS_X64 };
enum { EAX, ECX, EDX, EBX, ESP, EBP, ESI, EDI, __NUM_REGS_X86 };

const char *reg64_names[__NUM_REGS_X64] = {
	"RAX", "RCX", "RDX", "RBX", "RSP", "RBP"
};

const char *reg86_names[__NUM_REGS_X86] = {
	"EAX", "ECX", "EDX", "EBX", "ESP", "EBP", "ESI", "EDI"
};

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
	int  elf_numsymb; //  Number of entries in the ST

	uint8_t *pc;
	uint8_t *text;
	Elf64_Addr  text_vaddr;

	Elf64_Xword stack[100];
	int  sptr;

	Elf64_Xword reg64[__NUM_REGS_X64];

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

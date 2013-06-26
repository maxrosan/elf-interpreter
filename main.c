
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <assert.h>
#include <stdint.h>
#include <endian.h>

#include "elf.h"
#include "emu.h"
#include "options.h"

static Program p;
static Options opt;

int main(int argc, char **argv) {
#define TRY(func, label, ...) if(func(&p, ##__VA_ARGS__)) goto label;

	options_init(&opt);
	
	if (options_parse(&opt, argc, argv)) {
		goto free_opt;
	}

	if (emu_open_file(&p, opt.filename)) {
		fprintf(stderr, "Failed to open %s\n", opt.filename);
		goto free_emu;
	}

	TRY(emu_verify_elf, free_emu);
	TRY(emu_sec_header, free_emu);
	TRY(emu_str_table, free_emu);	
	TRY(emu_program_header, free_emu);
	TRY(emu_load_strtable, free_emu);
	TRY(emu_load_symbols, free_emu);
	TRY(emu_load_address, free_emu);
	
	TRY(emu_translate, free_emu);

free_emu:
	emu_free(&p);
free_opt:
	options_free(&opt);

	return EXIT_SUCCESS;
}

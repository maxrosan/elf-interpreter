
#include "emu.h"

int emu_open_file(Program *p, char *filename) {

	FILE *fd;

	fd = fopen(filename, "r");
	p->fd = fd;

	p->elf_sec = NULL;
	p->elf_str = NULL;
	p->elf_phr = NULL;
	p->elf_strtab = NULL;

	return !fd;
}

void emu_free(Program *p) {
	assert(p != NULL);

	if (p->fd) {
		fclose(p->fd);
	}

	if (p->elf_sec) {
		free(p->elf_sec);
	}

	if (p->elf_str) {
		free(p->elf_str);
	}

	if (p->elf_phr) {
		free(p->elf_phr);
	}

	if (p->elf_strtab) {
		free(p->elf_strtab);
	}
}

int emu_verify_elf(Program *p) {

	assert(p != NULL);

	char magic_num[4] = {0x7F, 0x45, 0x4c, 0x46};
	char header[EI_NIDENT];

	fread(header, 1, EI_NIDENT, p->fd);

	if (memcmp(header, magic_num, 4)) {
		fprintf(stderr, "File is not ELF\n");
		return -1;
	}

	switch (header[4]) {
		case 2:
			p->is_x64 = 1;
			break;
		default:
			fprintf(stderr, "Invalid class\n");
			return -1;
	}


	rewind(p->fd);

	if (p->is_x64) {
		Elf64_Ehdr *h = &p->elf_header.v64;

		fread(h, 1, sizeof(*h), p->fd);

		if (h->e_type != 2) {
			fprintf(stderr, "File isn't executable\n");
			return -1;
		}

		if (h->e_machine != 62) {
			fprintf(stderr, "It isn't for AMD64\n");
			return -1;
		}

		if (h->e_ident[5] == 0 || h->e_ident[5] > 2) {
			fprintf(stderr, "Invalid value for EI_DATA\n");
			return -1;
		}
	} else {
		fprintf(stderr, "Architecture not supported\n");
		return -1;
	}


	return 0;
}

int emu_sec_header(Program *p) {

	assert(p != NULL);

	if (p->is_x64) {

		Elf64_Shdr *secs;
		Elf64_Ehdr *h = &p->elf_header.v64;
		int i;

		fseek(p->fd, h->e_shoff, SEEK_SET);

		if (h->e_shnum == 0) {
			fprintf(stderr, "invalid number of sections\n");
			return -1;
		}

		if (h->e_shentsize != sizeof(Elf64_Shdr)) {
			fprintf(stderr, "invalid entry size\n");
			return -1;
		}
		
		p->elf_sec = malloc(sizeof(Elf64_Shdr) * h->e_shnum);
		fread(p->elf_sec, sizeof(Elf64_Shdr), h->e_shnum, p->fd);

		secs = (Elf64_Shdr*) p->elf_sec;

		//
		printf("Section header table\n");
		for (i = 0; i < h->e_shnum; i++) {
			printf("name = %d, type = %d\n", secs[i].sh_name, secs[i].sh_type);
		}
		//

	} else {
		fprintf(stderr, "Arch not supported\n");
		return -1;
	}

	return 0;
}

int emu_str_table(Program *p) {

	if (p->is_x64) {
		Elf64_Ehdr *h;
		Elf64_Shdr *secs;
		Elf64_Shdr *strtabsec;

		h = &p->elf_header.v64;

		if (h->e_shstrndx >= SHN_LORESERVE) {
			fprintf(stderr, "Op. not supported\n");
			return -1;
		}

		secs = (Elf64_Shdr*) p->elf_sec;
		strtabsec = &secs[h->e_shstrndx];

		if (strtabsec->sh_type != SHT_STRTAB) {
			fprintf(stderr, "Invalid value for strtabsec->type\n");
			return -1;
		}

		printf("shstrndx = %u\n", h->e_shstrndx);

		if (strtabsec->sh_size > 0) {
			int i;

			fseek(p->fd, strtabsec->sh_offset, SEEK_SET);
			p->elf_str = (char*) malloc(strtabsec->sh_size);
			fread(p->elf_str, 1, strtabsec->sh_size, p->fd);

			printf("Sections with string [ %d ] \n", strtabsec->sh_size);
			for (i = 0; i < h->e_shnum; i++) {
				printf("name[%d] = %s\n", i, p->elf_str + secs[i].sh_name);
			}
		}

	} else {
		fprintf(stderr, "Arch not supported\n");
		return -1;
	}

	return 0;
}

int emu_program_header(Program *p) {

	if (p->is_x64) {

		Elf64_Ehdr *h;
		Elf64_Shdr *secs;
		Elf64_Shdr *strtabsec;
		Elf64_Phdr *hdrs;

		int text_entry = 0, i;

		h = &p->elf_header.v64;

		if (h->e_phnum == 0) {
			fprintf(stderr, "Invalid number for number of phrs\n");
			return -1;
		}
		
		fseek(p->fd, h->e_phoff, SEEK_SET);

		if (h->e_phentsize != sizeof(Elf64_Phdr)) {
			fprintf(stderr, "Invalid size of PHDR\n");
			return -1;
		}

		hdrs = (Elf64_Phdr*) malloc(sizeof(Elf64_Phdr) * h->e_phnum);
		p->elf_phr = (void*) hdrs;

		fread(hdrs, sizeof(Elf64_Phdr), h->e_phnum, p->fd);
		
		for (i = 0; i < h->e_phnum && !(hdrs[i].p_type == 1 && hdrs[i].p_flags ==  5); i++) {
			printf("seg %d %d %x\n", i, hdrs[i].p_type, hdrs[i].p_flags);
		}
		
		if (i == h->e_phnum) {
			fprintf(stderr, "Failed to find .text entry\n");
			return -1;
		}

	} else {
		fprintf(stderr, "Arch not supported\n");
		return -1;
	}

	return 0;
}

static void* __sec_get_ptr(Program *p, const char *name, int *idxret) {

	Elf64_Ehdr *h;

	assert(p != NULL);
	assert(name != NULL);

	if (p->is_x64) {
		int idx, i;
		Elf64_Ehdr *h;
		Elf64_Shdr *secs;

		h = &p->elf_header.v64;
		secs = (Elf64_Shdr*) p->elf_sec;

		for (i = 1; i < h->e_shnum; i++) {
			if (!strcmp(p->elf_str + secs[i].sh_name, name)) {
				idx = i;
				i = h->e_shnum + 1;
			}
		}

		if (idxret) {
			*idxret = idx;
		}

		if (i > h->e_shnum) {
			void *mem;

			mem = malloc(secs[idx].sh_size);
			pread(fileno(p->fd), mem, secs[idx].sh_size, secs[idx].sh_offset);
			return mem;
		}

	}

	return NULL;

}

int emu_load_strtable(Program *p) {

	if (p->is_x64) {

		p->elf_strtab = (char*) __sec_get_ptr(p, ".strtab", NULL);

		if (p->elf_strtab == NULL) {
			fprintf(stderr, ".strtab not found\n");
			return -1;		
		}

	} else {
		fprintf(stderr, "Arch not supported\n");
		return -1;
	}


	return 0;
}

int emu_load_symbols(Program *p) {

	if (p->is_x64) {

		Elf64_Sym *symtab;
		int idx, i, j;
		Elf64_Ehdr *h;
		Elf64_Shdr *secs;

		h = &p->elf_header.v64;
		secs = (Elf64_Shdr*) p->elf_sec;

		symtab = (Elf64_Sym*) __sec_get_ptr(p, ".symtab", &idx);
		
		if (symtab == NULL) { 
			fprintf(stderr, ".symtab not found\n");
			return -1;		
		}

		p->elf_symtab = symtab;

		for (i = 0, j = 0; i < secs[idx].sh_size; i += secs[idx].sh_entsize, j++) {
			printf("sym %s\n", p->elf_strtab + symtab[j].st_name);
		}
	
	} else {
		fprintf(stderr, "Arch not supported\n");
		return -1;
	}

	return 0;

}

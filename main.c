
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <assert.h>
#include <stdint.h>
#include <endian.h>

typedef uint8_t		Elf_Byte;

typedef uint32_t	Elf32_Addr;	/* Unsigned program address */
typedef uint32_t	Elf32_Off;	/* Unsigned file offset */
typedef int32_t		Elf32_Sword;	/* Signed large integer */
typedef uint32_t	Elf32_Word;	/* Unsigned large integer */
typedef uint16_t	Elf32_Half;	/* Unsigned medium integer */

typedef uint64_t	Elf64_Addr;
typedef uint64_t	Elf64_Off;
typedef int32_t		Elf64_Shalf;

typedef int32_t		Elf64_Sword;
typedef uint32_t	Elf64_Word;

typedef int64_t		Elf64_Sxword;
typedef uint64_t	Elf64_Xword;

typedef uint32_t	Elf64_Half;
typedef uint16_t	Elf64_Quarter;

#define EI_NIDENT 16

#define ELFDATA2LSB 1
#define ELFDATA2MSB 2

#define SHN_UNDEF 	0
#define SHN_LORESERVE 	0xff00
#define SHN_LOPROC 	0xff00
#define SHN_HIPROC 	0xff1f
#define SHN_LOOS 	0xff20
#define SHN_HIOS 	0xff3f
#define SHN_ABS 	0xfff1
#define SHN_COMMON 	0xfff2
#define SHN_XINDEX 	0xffff
#define SHN_HIRESERVE 	0xffff

/* sh_type */
#define SHT_NULL	0		/* inactive */
#define SHT_PROGBITS	1		/* program defined information */
#define SHT_SYMTAB	2		/* symbol table section */
#define SHT_STRTAB	3		/* string table section */
#define SHT_RELA	4		/* relocation section with addends*/
#define SHT_HASH	5		/* symbol hash table section */
#define SHT_DYNAMIC	6		/* dynamic section */
#define SHT_NOTE	7		/* note section */
#define SHT_NOBITS	8		/* no space section */
#define SHT_REL		9		/* relation section without addends */
#define SHT_SHLIB	10		/* reserved - purpose unknown */
#define SHT_DYNSYM	11		/* dynamic symbol table section */
#define SHT_NUM		12		/* number of section types */
#define SHT_LOPROC	0x70000000	/* reserved range for processor */
#define SHT_HIPROC	0x7fffffff	/*  specific section header types */
#define SHT_LOUSER	0x80000000	/* reserved range for application */
#define SHT_HIUSER	0xffffffff	/*  specific indexes */

typedef struct {
	Elf32_Word	sh_name;
	Elf32_Word	sh_type;
	Elf32_Word	sh_flags;
	Elf32_Addr	sh_addr;
	Elf32_Off	sh_offset;
	Elf32_Word	sh_size;
	Elf32_Word	sh_link;
	Elf32_Word	sh_info;
	Elf32_Word	sh_addralign;
	Elf32_Word	sh_entsize;
} Elf32_Shdr;

typedef struct {
	Elf64_Word	sh_name;
	Elf64_Word	sh_type;
	Elf64_Xword	sh_flags;
	Elf64_Addr	sh_addr;
	Elf64_Off	sh_offset;
	Elf64_Xword	sh_size;
	Elf64_Word	sh_link;
	Elf64_Word	sh_info;
	Elf64_Xword	sh_addralign;
	Elf64_Xword	sh_entsize;
} Elf64_Shdr;

/* ELF Header */
typedef struct {
	unsigned char	e_ident[EI_NIDENT]; /* ELF Identification */
	Elf32_Half	e_type;		/* object file type */
	Elf32_Half	e_machine;	/* machine */
	Elf32_Word	e_version;	/* object file version */
	Elf32_Addr	e_entry;	/* virtual entry point */
	Elf32_Off	e_phoff;	/* program header table offset */
	Elf32_Off	e_shoff;	/* section header table offset */
	Elf32_Word	e_flags;	/* processor-specific flags */
	Elf32_Half	e_ehsize;	/* ELF header size */
	Elf32_Half	e_phentsize;	/* program header entry size */
	Elf32_Half	e_phnum;	/* number of program header entries */
	Elf32_Half	e_shentsize;	/* section header entry size */
	Elf32_Half	e_shnum;	/* number of section header entries */
	Elf32_Half	e_shstrndx;	/* section header table's "section  header string table" entry offset */
} Elf32_Ehdr;

typedef struct {
	unsigned char	e_ident[EI_NIDENT];	/* Id bytes */
	Elf64_Quarter	e_type;			/* file type */
	Elf64_Quarter	e_machine;		/* machine type */
	Elf64_Half	e_version;		/* version number */
	Elf64_Addr	e_entry;		/* entry point */
	Elf64_Off	e_phoff;		/* Program hdr offset */
	Elf64_Off	e_shoff;		/* Section hdr offset */
	Elf64_Half	e_flags;		/* Processor flags */
	Elf64_Quarter	e_ehsize;		/* sizeof ehdr */
	Elf64_Quarter	e_phentsize;		/* Program header entry size */
	Elf64_Quarter	e_phnum;		/* Number of program headers */
	Elf64_Quarter	e_shentsize;		/* Section header entry size */
	Elf64_Quarter	e_shnum;		/* Number of section headers */
	Elf64_Quarter	e_shstrndx;		/* String table index */
} Elf64_Ehdr;

typedef struct {

	FILE *fd;
	int is_x64;
	union { 
		Elf32_Ehdr v32;
		Elf64_Ehdr v64;
	} elf_header;

	void *elf_sec;

} Program;

typedef struct {

	char *filename;

} Options;

int emu_open_file(Program *p, char *filename) {

	FILE *fd;

	fd = fopen(filename, "r");
	p->fd = fd;

	p->elf_sec = NULL;

	return !fd;
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

		printf("Section header table\n");
		for (i = 0; i < h->e_shnum; i++) {
			printf("name = %d, type = %d\n", secs[i].sh_name, secs[i].sh_type);
		}

	}
}

void emu_free(Program *p) {
	assert(p != NULL);

	if (p->fd) {
		fclose(p->fd);
	}

	if (p->elf_sec) {
		free(p->elf_sec);
	}
}


void options_init(Options *options) {
	assert(options != NULL);

	options->filename = NULL;
}

void options_free(Options *options) {

	assert(options != NULL);

	if (options->filename) {
		free(options->filename);
	}
}

int options_parse(Options *options, int argc, char **argv) {

	int opt, ret = 0;

	assert(options != NULL);

	while ((opt = getopt(argc, argv, "f:")) != -1) {
		switch (opt) {
			case 'f':
				options->filename = strdup(optarg);
			break;
			default:
				fprintf(stderr, "Unknow option");
				ret = -1;
		}
	}

	if (options->filename == NULL) {
		fprintf(stderr, "No file specified\n");
		ret = -1;
	}

	return ret;

}

int main(int argc, char **argv) {

	Program p;
	Options opt;

	options_init(&opt);
	
	if (options_parse(&opt, argc, argv)) {
		goto free_opt;
	}

	if (emu_open_file(&p, opt.filename)) {
		fprintf(stderr, "Failed to open %s\n", opt.filename);
		goto free_emu;
	}

	if (emu_verify_elf(&p)) {
		goto free_emu;
	}

	if (emu_sec_header(&p)) {
		goto free_emu;
	}
	
free_emu:
	emu_free(&p);
free_opt:
	options_free(&opt);

	return EXIT_SUCCESS;
}

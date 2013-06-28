
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdint.h>

int main(int argc, char **argv) {

	if (argc < 2) {
		fprintf(stderr, "Invalid number of arguments\n");
		return -1;
	}

	char *base = argv[1];
	char *num  = argv[2];
	int  len   = strlen(num);

	uint64_t res = 0;
	uint32_t i   = 0;

	if (strlen(base) > 1) {
		fprintf(stderr, "Invalid base\n");
		return -1;
	}

	switch (base[0]) {
		case 'b':
			while (num[i]) {
				if (num[i] != '0' && num[i] != '1') {
					fprintf(stderr, "Invalid input\n");
					return -1;
				}
	
				res = (res << 1) + (num[i] - '0');
				i++;
			}
			break;

		default:
			fprintf(stderr, "Invalid base\n");
	}

	printf("result = %u\n", res);

	return EXIT_SUCCESS;
}

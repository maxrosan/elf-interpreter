
#include "options.h"

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

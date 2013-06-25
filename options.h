
#include <stdio.h>
#include <unistd.h>
#include <assert.h>

typedef struct {

	char *filename;

} Options;


void options_init(Options *options);
int options_parse(Options *options, int argc, char **argv);

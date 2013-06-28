
CC=gcc
DEPS=options.h emu.h

all: main ex convert_base

%.o: %c $(DEPS)
	$(CC) -c -o $@ $<

main: emu.h main.o emu.o options.o
	$(CC) -o $@ $^

ex: ex.o
	$(CC) -ggdb -o $@ $^

convert_base: convert_base.o
	$(CC) -ggdb -o $@ $^

clean:
	rm *.o && rm main

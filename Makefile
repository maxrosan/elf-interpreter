
CC=gcc
DEPS=options.h emu.h

all: main ex

%.o: %c $(DEPS)
	$(CC) -c -o $@ $<

main: main.o emu.o options.o
	$(CC) -o $@ $^

ex: ex.o
	$(CC) -ggdb -o $@ $^

clean:
	rm *.o && rm main

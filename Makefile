
CC=gcc
DEPS=options.h emu.h

all: main

%.o: %c $(DEPS)
	$(CC) -c -o $@ $<

main: main.o emu.o options.o
	$(CC) -o $@ $^

clean:
	rm *.o && rm main

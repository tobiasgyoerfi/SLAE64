all: decoder encoder.py decoder_wrapper

decoder: decoder.nasm
	nasm decoder.nasm -f elf64 -o decoder.o
	ld decoder.o -o decoder

decoder_wrapper: decoder_wrapper.c
	gcc -fno-stack-protector -z execstack decoder_wrapper.c -o decoder_wrapper

clean:
	rm *.o decoder decoder_wrapper

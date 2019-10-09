all: tcp_reverse tcp_reverse_wrapper

tcp_reverse: tcp_reverse.nasm
	nasm tcp_reverse.nasm -f elf64 -o tcp_reverse.o
	ld tcp_reverse.o -o tcp_reverse

tcp_reverse_wrapper: tcp_reverse_wrapper.c
	gcc -fno-stack-protector -z execstack tcp_reverse_wrapper.c -o tcp_reverse_wrapper

clean:
	rm *.o tcp_reverse tcp_reverse_wrapper
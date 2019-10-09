all: tcp_bind tcp_bind_wrapper

tcp_bind: tcp_bind.nasm
	nasm tcp_bind.nasm -f elf64 -o tcp_bind.o
	ld tcp_bind.o -o tcp_bind

tcp_bind_wrapper: tcp_bind_wrapper.c
	gcc -fno-stack-protector -z execstack tcp_bind_wrapper.c -o tcp_bind_wrapper

clean:
	rm *.o tcp_bind tcp_bind_wrapper
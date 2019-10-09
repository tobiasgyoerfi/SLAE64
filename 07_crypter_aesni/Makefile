all: decrypter decrypter_wrapper

decrypter: decrypter.nasm
	nasm decrypter.nasm -f elf64 -o decrypter.o
	ld -N decrypter.o -o decrypter

decrypter_wrapper: decrypter_wrapper.c
	gcc -fno-stack-protector -z execstack decrypter_wrapper.c -o decrypter_wrapper

clean:
	rm decrypter decrypter_wrapper *.o
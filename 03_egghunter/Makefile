all: egghunter egghunter_wrapper

egghunter: egghunter.nasm
	nasm egghunter.nasm -f elf64 -o egghunter.o
	ld egghunter.o -o egghunter

egghunter_wrapper: egghunter_wrapper.c
	gcc -fno-stack-protector -z execstack egghunter_wrapper.c -o egghunter_wrapper

clean:
	rm *.o egghunter egghunter_wrapper
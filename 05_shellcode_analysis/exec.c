#include<stdio.h>
#include<string.h>

void main()
{
    unsigned char buf[] = 
        "\x6a\x3b\x58\x99\x48\xbb\x2f\x62\x69\x6e\x2f\x73\x68\x00\x53"
        "\x48\x89\xe7\x68\x2d\x63\x00\x00\x48\x89\xe6\x52\xe8\x10\x00"
        "\x00\x00\x74\x6f\x75\x63\x68\x20\x2f\x74\x6d\x70\x2f\x74\x65"
        "\x73\x74\x00\x56\x57\x48\x89\xe6\x0f\x05";


	int (*ret)() = (int(*)())buf;
	ret();
}

	
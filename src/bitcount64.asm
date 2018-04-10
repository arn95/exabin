segment .text
global _bitcount	; declare a global symbol for our function
					;  and declare the 'function' symbol global
_bitcount:
	push rbp		; save the previous frame pointer
	mov rbp, rsp	; setup a new frame for this function
	xor eax, eax	; clear eax
	xor ebx, ebx	; clear ebx
	nop
	movzx ebx, dil	; move the lower 8 bits of edi to ebx (edi has 1st arg in x64)
	popcnt eax, ebx	; count the number of set bits in ebx and return the result in eax
	mov rsp, rbp	; cleanup our stack frame
	pop rbp			
	ret				; return from this function (eax represents an int)

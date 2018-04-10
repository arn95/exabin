segment .text
global bitcount		; declare a global symbol for our function
					;  and declare the 'function' symbol global
bitcount:
	push ebp		; save the previous frame pointer
	mov ebp, esp	; setup a new frame for this function
	xor eax, eax	; clear eax
	xor ebx, ebx	; clear ebx
	nop
	movzx ebx, byte [ebp+8]	; load passed argument into ebx
	popcnt eax, ebx	; count the number of set bits in ebx and return the result in eax
	mov esp, ebp	; cleanup our stack frame
	pop ebp			; restore the pointer to the previous frame
	ret				; return from this function
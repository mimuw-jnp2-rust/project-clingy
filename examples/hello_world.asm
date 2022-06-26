section .data
    hello_cruel_world_len dd 19

section .text
    extern hello_cruel_world_str
    extern exit
    global _start
    _start:
        mov rax, 1
        mov rdi, 1
        mov rsi, hello_cruel_world_str 
        mov edx, [hello_cruel_world_len]
        syscall
        call exit

section .data
    global hello_cruel_world_str
    hello_cruel_world_str db "Hello, cruel world!", 00

section .text
    global exit
    exit:
        mov rax, 60
        mov rdi, 0
        syscall

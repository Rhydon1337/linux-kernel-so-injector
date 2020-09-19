#define RTLD_NOW  0x00002 
        .text
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

        movq $0xffffffffffffffff, %rdi 
        movq $RTLD_NOW, %rsi
        call 0xffffffffffffffff
        
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

        jmp 0xffffffffffffffff
end_of_shellcode:
        .end

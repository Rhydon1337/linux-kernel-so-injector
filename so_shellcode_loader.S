#pragma GCC push_options
#pragma GCC optimize ("O0")

#define MAGIC_SO_PATH 0x1234567890abcdea
#define MAGIC_PREV_IP 0x1234567890abcdeb
#define MAGIC_SO_LOAD_FUNCTION 0x1234567890abcded

#define RTLD_NOW  0x00002 
#define __RTLD_DLOPEN	0x80000000

        .text
        .align 16
        .global shellcode
        .global end_of_shellcode
shellcode:
        # call __libc_dlopen_mode and pssing parameters
        nop
        nop
        nop
        nop
        nop
     	pushq %rax
     	pushq %rbx
        pushq %rcx
        pushq %rdx
        pushq %rdi
        pushq %rsi
        pushq %rsp
        pushq %rbp
        pushq %r8
        pushq %r9
        pushq %r10
        pushq %r11
        pushq %r12
        pushq %r13
        pushq %r14
        pushq %r15
        pushfq

        movq %rsp, %rbx
        andq $0xFFFFFFFFFFFFFFF0, %rsp

        movq $MAGIC_SO_LOAD_FUNCTION, %rax
        movq $MAGIC_SO_PATH, %rdi 
        mov $(RTLD_NOW | __RTLD_DLOPEN), %rsi
        callq *%rax

        movq %rbx, %rsp

        popfq
        popq %r15
        popq %r14
        popq %r13
        popq %r12
        popq %r11
        popq %r10
        popq %r9
        popq %r8
        popq %rbp
        popq %rsp
        popq %rsi
        popq %rdi
        popq %rdx
        popq %rcx
     	popq %rbx
  	popq %rax

        movq $MAGIC_PREV_IP, %r15
        jmpq *%r15
        
end_of_shellcode:
        .end


#pragma GCC pop_options
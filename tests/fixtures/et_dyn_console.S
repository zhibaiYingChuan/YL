.section .rodata
message:
    .ascii "daoti-et-dyn-ok\n"
.set message_len, . - message

.section .text
.globl _start
.type _start, @function
_start:
    mov $1, %rax
    mov $1, %rdi
    lea message(%rip), %rsi
    mov $message_len, %rdx
    syscall
    mov $60, %rax
    xor %rdi, %rdi
    syscall
.size _start, .-_start

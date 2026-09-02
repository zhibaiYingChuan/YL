.text
.globl _start
.type _start, @function
_start:
    # 第一个 GD TLS 描述符：应解析到 module_id=1。
    leaq daoti_tls_value@tlsgd(%rip), %rdi
    call __tls_get_addr@PLT
    movl (%rax), %ebx

    # 第二个 GD TLS 描述符：应解析到 module_id=2，验证多依赖 DTV 槽位。
    leaq daoti_tls_value_b@tlsgd(%rip), %rdi
    call __tls_get_addr@PLT
    addl (%rax), %ebx

    movl %ebx, %edi
    movl $60, %eax
    syscall
.size _start, .-_start

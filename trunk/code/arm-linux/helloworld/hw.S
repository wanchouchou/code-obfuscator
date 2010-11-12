@filename: hw.S

.text
.align 2
.global _start

@ ssize_t sys_write(unsigned int fd, const char * buf, size_t count)
@         r7                 r0      r1                r2

_start:
    adr     r1, msg         @ Address
    mov     r0, #1          @ STDOUT
    mov     r2, #16         @ Length
    mov     r7, #4          @ sys_write
    svc     0x00000000

@ int sys_exit(int status)
@     r7       r0

    mov     r0, #0          @ Return code
    mov     r7, #1          @ sys_exit
    svc     0x00000000

.align 2

msg:
    .asciz "Hello Android!\n\n"

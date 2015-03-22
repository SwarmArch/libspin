# Simply exits with code 42
.globl _start
.text
_start:
	mov    $42, %rdi
	mov    $60, %rax
	syscall

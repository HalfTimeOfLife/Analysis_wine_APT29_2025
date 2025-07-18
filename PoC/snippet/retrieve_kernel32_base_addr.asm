; https://www.bordergate.co.uk/windows-x64-shellcode-development/

start:
    sub rsp, 0x400

locate_kernel32_base:
    mov rax, fs:[0x30]      ; https://en.wikipedia.org/wiki/Win32_Thread_Information_Block
    mov rax, [rax + 0x18]
    mov r12, [rax + 0x20]   ; BYTE Reserved1[8] = 8 bytes and   PVOID Reserved2[3] = 8*3 = 24 bytes -- 32 bytes = 0x20

next_module:
    lodsq

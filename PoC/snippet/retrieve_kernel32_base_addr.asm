; https://www.bordergate.co.uk/windows-x64-shellcode-development/

section .data
    wfmt dw '%', '.', '*', 's', 10, 0   ; L"%.*s\n"

section .text
    extern wprintf
    global main

main:
    sub rsp, 0x28

locate_kernel32_base:
    mov rax, qword gs:[0x60]      ; https://en.wikipedia.org/wiki/Win32_Thread_Information_Block
    mov rax, [rax + 0x18]   ; Ldr at 0x14 but for alignment purpose 0x18
    mov r13, [rax + 0x20]   ; InMemoryOrderModuleList || BYTE Reserved1[8] = 8 bytes and   PVOID Reserved2[3] = 8*3 = 24 bytes -- 32 bytes = 0x20
    mov r12, r13            ; r12 will be used to traverse the list
next_module:
    sub r12, 0x20           ; Get start of LDR_DATA_TABLE_ENTRY struct
    mov cx, [r12+0x58]      ; Get length of BaseDllName from UNICODE_STRING
    mov rsi, [r12 + 0x60]   ; Get BaseDllName from LDR_DATA_TABLE_ENTRY || https://www.geoffchappell.com/studies/windows/km/ntoskrnl/inc/api/ntldr/ldr_data_table_entry.htm
    cmp cx, 0x0c            ; Check if length is 12 bytes (ASCII "kernel32.dll")
    je kernel32_found       ; If not, go to next module

    add r12, 0x20           ; restore r12 to LIST_ENTRY pointer
    mov r12, [r12]          ; r12 = Flink (next module's LIST_ENTRY)
    cmp r12, r13            ; compare to list head
    jne next_module

    jmp not_found           ; If nothing found exit with error


kernel32_found:
    int 3
    lea rcx, [rel wfmt]     ; Load address of format string
    movzx rdx, cx           ; Load length of the string
    shr rdx, 1              ; Convert length from bytes to characters (UTF-16)
    mov r8, rsi             ; Load address of the wide string buffer

    sub rsp, 0x28           ; Adjust stack for function call
    call wprintf

not_found:
    int 3
    add rsp, 0x28           ; Restore stack
    ret


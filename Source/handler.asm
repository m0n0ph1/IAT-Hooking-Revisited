bits 32

push ebp;

xor ebx, ebx

jmp short start

;================================
;Find Function
;================================
find_function:

;================================
;Find Kernel32 Base
;================================
mov edi, [fs:ebx+0x30]
mov edi, [edi+0x0c]
mov edi, [edi+0x1c]

module_loop:
mov eax, [edi+0x08]
mov esi, [edi+0x20]
mov edi, [edi]

cmp byte [esi+0x0C], '3'
jne module_loop

;================================
;Kernel32 PE Header
;================================
mov edi, eax
add edi, [eax+0x3c]

;================================
; Export directory table
;================================
;0x00 Export Flags
;0x04 Time/Date Stamp
;0x08 Major Version
;0x0A Minor Version
;0x0C Name RVA
;0x10 Ordinal Base
;0x14 Address Table Entries
;0x18 Number Of Names
;0x1c Address Table RVA
;0x20 Name Pointer Table RVA
;0x24 Ordinal Table RVA
;================================

;================================
;Kernel32 Export Directory Table
;================================
mov edx, [edi+0x78]
add edx, eax

;================================
;Kernel32 Name Pointers
;================================
mov edi, [edx+0x20]
add edi, eax

;================================
;Find LoadLibraryA
;================================
mov ebp, ebx
name_loop:
mov esi, [edi+ebp*0x4]
add esi, eax
inc ebp
mov ecx, [esp+0x4]
cmp dword [esi], ecx
jne name_loop
mov ecx, [esp+0x8]
cmp dword [esi+0x4], ecx
jne name_loop

;================================
;LoadLibraryA Ordinal
;================================
mov edi, [edx+0x24]
add edi, eax
mov bp, [edi+ebp*0x2]

;================================
;LoadLibraryA Address
;================================
mov edi, [edx+0x1C]
add edi, eax
mov edi, [edi+(ebp-0x1)*0x4] ;subtract ordinal base
add eax, edi
ret

start:

;================================
;Call LoadLibraryA
;================================
push 0x7262694C ;Libr
push 0x64616F4C ;Load
call find_function

xor ecx, ecx
mov cx, 0x3233   ;32
push ecx

push 0x72657375  ;user

push esp ; lpFileName

call eax
push eax

;================================
;Call GetProcAddress
;================================
push 0x41636F72 ;rocA
push 0x50746547 ;GetP
call find_function

pop ecx
pop ecx
pop ecx

push 0x041786F0; oxA
shr dword [esp], 0x4
push 0x42656761; ageB
push 0x7373654D; Mess

push esp ; lpProcName
push ecx ; hModule

call eax

;================================
;Call MessageBoxA
;================================
push ebx
push ebx
push ebx
push ebx
call eax

mov ecx, 7
pop_loop:
pop eax
loop pop_loop

pop ebp

mov eax, 0xDEADBEEF
jmp eax


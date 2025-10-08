.data
	wSystemCall			DWORD	0h	
	qSyscallInsAdress	QWORD	0h	


.code

	SetSSn proc	
		xor rax, rax					; rax = 0
		mov wSystemCall, eax			; wSystemCall = 0
		mov qSyscallInsAdress, rax		; qSyscallInsAdress = 0
		xor r9, r9						; r9 = 0
		mov r9d, ecx					; r9 = ssn
		mov wSystemCall, r9d			; wSystemCall = r9 = ssn
		xor r9, r9						; r9 = 0
		mov r9, rdx						; r9 = AddressOfASyscallInst
		mov qSyscallInsAdress, r9		; qSyscallInsAdress = r9 = AddressOfASyscallInst
		ret
	SetSSn endp


; SetSSn should look like this :
	;SetSSn PROC
	;	mov wSystemCall, 0h
	;	mov qSyscallInsAdress, 0h
	;	mov wSystemCall, ecx
	;	mov qSyscallInsAdress, rdx
	;	ret
	;SetSSn ENDP


	RunSyscall proc
		xor r11, r11						; r11 = 0
		mov rax, rcx						; rax = rcx
		xor rcx, rcx
		mov r10, rax						; r10 = rax	= rcx
		mov eax, wSystemCall				; eax = ssn
		jmp Run								; execute 'Run'
		xor eax, eax	; wont run
		xor rdx, rcx	; wont run
		shl r11, 2		; wont run
	Run:
		jmp qword ptr [qSyscallInsAdress]
		xor r11, r11					; r11 = 0
		mov qSyscallInsAdress, r10		; qSyscallInsAdress = 0
		ret
	RunSyscall endp


; RunSyscall should look like this :
	;RunSyscall PROC
	;	mov r10, rcx
	;	mov eax, wSystemCall
	;	jmp qword ptr [qSyscallInsAdress]
	;	ret
	;RunSyscall ENDP


end
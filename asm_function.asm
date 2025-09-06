.code

PUBLIC rdtsc_asm
PUBLIC xgetbv_asm
PUBLIC fnstcw_asm
PUBLIC read_mxcsr_asm
; uint64_t xgetbv_asm(uint32_t ecx)

fnstcw_asm PROC
    fnstcw [rcx]   
    ret
fnstcw_asm ENDP

read_mxcsr_asm PROC
    stmxcsr [rcx]  
    ret
read_mxcsr_asm ENDP

xgetbv_asm PROC
    ; ecx is in ecx already
    xgetbv              ; output edx:eax
    shl rdx, 32         ; shift edx to high 32 bits
    or rax, rdx         ; combine edx:eax to rax
    ret

xgetbv_asm ENDP

PUBLIC rdtsc_asm
; uint64_t rdtsc_asm()

rdtsc_asm PROC
    rdtsc             
    shl rdx, 32       
    or rax, rdx        
    ret
rdtsc_asm ENDP

ReadGDTR PROC
    sgdt fword ptr [rcx]   ; GDTR -> [RCX]
    ret
ReadGDTR ENDP

END

#ifndef OFFSETS_2_20_H
#define OFFSETS_2_20_H

uint64_t g_sym_map_220[] = {
    0x4CB3B50,          // KERNEL_SYM_DMPML4I
    0x4CB3B54,          // KERNEL_SYM_DMPDPI
    0x4CB38AC,          // KERNEL_SYM_PML4PML4I
    0x4CB38C8,          // KERNEL_SYM_PMAP_STORE
    0x7C40000,          // KERNEL_SYM_DATA_CAVE
    0x0044000,          // KERNEL_SYM_CODE_CAVE
    0x1CDE5B0,          // KERNEL_SYM_PS4_SYSENT
    0x1CE6DD0,          // KERNEL_SYM_PPR_SYSENT
    0x0042000,          // KERNEL_SYM_GADGET_JMP_PTR_RSI
    0x245B0C0,          // KERNEL_SYM_HV_JMP_TABLE
    0x248EBB0,          // KERNEL_SYM_HIJACKED_JMP_PTR
};

uint64_t g_patch_map_220[] = {
    0x05809D0,          // KERNEL_PATCH_HAS_MMAP_SELF_CAPABILITY
    0x05809E0,          // KERNEL_PATCH_IS_ALLOWED_TO_MMAP_SELF
    0x09A6409,          // KERNEL_PATCH_MMAP_SELF_CALL_IS_LOADABLE
    0x02A69F0,          // KERNEL_PATCH_SYS_GETGID
};

uint64_t g_gadget_map_220[] = {
    0x103c4e,           // KERNEL_GADGET_RET
    0x16aff2,           // KERNEL_GADGET_INFLOOP
    0xadfb40,           // KERNEL_GADGET_HYPERCALL_SET_CPUID_PS4
    0xae01af,           // KERNEL_GADGET_RETURN_ADDR
    0x1a6878,           // KERNEL_GADGET_POP_RDI
    0x125c34,           // KERNEL_GADGET_POP_RSI
    0x1984e2,           // KERNEL_GADGET_POP_RDX
    0x1c34d0,           // KERNEL_GADGET_POP_RAX
    0x133166,           // KERNEL_GADGET_POP_RBX
    0x201f99,           // KERNEL_GADGET_ADD_RAX_RDX
    0x672937,           // KERNEL_GADGET_MOV_R9_QWORD_PTR_RDI_48
    0x62cda1,           // KERNEL_GADGET_POP_R12
    0x3b2ae6,           // KERNEL_GADGET_MOV_QWORD_PTR_RDI_RSI
    0x14acb7,           // KERNEL_GADGET_POP_RSP
    0x16b590,           // KERNEL_GADGET_MOV_RAX_QWORD_PTR_RAX
    0x16b737,           // KERNEL_GADGET_MOV_QWORD_PTR_RAX_0
    0x2488f0,           // KERNEL_GADGET_SETJMP
    0x248920,           // KERNEL_GADGET_LONGJMP
    0xb5d12c,           // KERNEL_GADGET_JOP1
    0x1d8c8f,           // KERNEL_GADGET_JOP2
};

#endif // OFFSETS_2_20_H
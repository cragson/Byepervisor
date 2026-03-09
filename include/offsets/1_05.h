#ifndef OFFSETS_1_05_H
#define OFFSETS_1_05_H

uint64_t g_sym_map_105[] = {
    0x4ADF5B0,          // KERNEL_SYM_DMPML4I
    0x4ADF5B4,          // KERNEL_SYM_DMPDPI
    0x4ADF30C,          // KERNEL_SYM_PML4PML4I
    0x4ADF328,          // KERNEL_SYM_PMAP_STORE
    0x7980000,          // KERNEL_SYM_DATA_CAVE
    0x0044000,          // KERNEL_SYM_CODE_CAVE
    0x1CA2690,          // KERNEL_SYM_PS4_SYSENT
    0x1CAA890,          // KERNEL_SYM_PPR_SYSENT
    0x0042000,          // KERNEL_SYM_GADGET_JMP_PTR_RSI
    0x23ebb98,          // KERNEL_SYM_HV_JMP_TABLE
    0x241aaf0,          // KERNEL_SYM_HIJACKED_JMP_PTR
};

uint64_t g_patch_map_105[] = {
    0x05A9C20,          // KERNEL_PATCH_HAS_MMAP_SELF_CAPABILITY
    0x05A9C30,          // KERNEL_PATCH_IS_ALLOWED_TO_MMAP_SELF
    0x0981909,          // KERNEL_PATCH_MMAP_SELF_CALL_IS_LOADABLE
    0x02F17D0,          // KERNEL_PATCH_SYS_GETGID
};

uint64_t g_gadget_map_105[] = {
    0x2,                // KERNEL_GADGET_RET
    0x1531f2,           // KERNEL_GADGET_INFLOOP
    0xaa9140,           // KERNEL_GADGET_HYPERCALL_SET_CPUID_PS4
    0xaa97b1,           // KERNEL_GADGET_RETURN_ADDR
    0x18ea78,           // KERNEL_GADGET_POP_RDI
    0x1230c4,           // KERNEL_GADGET_POP_RSI
    0x1100c2,           // KERNEL_GADGET_POP_RDX
    0x1ab6d0,           // KERNEL_GADGET_POP_RAX
    0x12d876,           // KERNEL_GADGET_POP_RBX
    0x1ea199,           // KERNEL_GADGET_ADD_RAX_RDX
    0x681cfb,           // KERNEL_GADGET_MOV_R9_QWORD_PTR_RDI_48
    0x646f21,           // KERNEL_GADGET_POP_R12
    0x3f2c36,           // KERNEL_GADGET_MOV_QWORD_PTR_RDI_RSI
    0x149b8f,           // KERNEL_GADGET_POP_RSP
    0x153790,           // KERNEL_GADGET_MOV_RAX_QWORD_PTR_RAX
    0x153937,           // KERNEL_GADGET_MOV_QWORD_PTR_RAX_0
    0x2309e0,           // KERNEL_GADGET_SETJMP
    0x230a10,           // KERNEL_GADGET_LONGJMP
    0xb1ecac,           // KERNEL_GADGET_JOP1
    0x1c0e8f,           // KERNEL_GADGET_JOP2
};

#endif // OFFSETS_1_05_H
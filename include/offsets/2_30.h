#ifndef OFFSETS_2_30_H
#define OFFSETS_2_30_H

uint64_t g_sym_map_230[] = {
    0x4CB3B50,          // KERNEL_SYM_DMPML4I
    0x4CB3B54,          // KERNEL_SYM_DMPDPI
    0x4CB38AC,          // KERNEL_SYM_PML4PML4I
    0x4CB38C8,          // KERNEL_SYM_PMAP_STORE
    0x7C40000,          // KERNEL_SYM_DATA_CAVE
    0x0044000,          // KERNEL_SYM_CODE_CAVE
    0x1CDE5C0,          // KERNEL_SYM_PS4_SYSENT
    0x1CE6DE0,          // KERNEL_SYM_PPR_SYSENT
    0x0042000,          // KERNEL_SYM_GADGET_JMP_PTR_RSI
    0x245be20,          // KERNEL_SYM_HV_JMP_TABLE
    0x248ebb0,          // KERNEL_SYM_HIJACKED_JMP_PTR
};

uint64_t g_patch_map_230[] = {
    0x0580D50,          // KERNEL_PATCH_HAS_MMAP_SELF_CAPABILITY
    0x0580D60,          // KERNEL_PATCH_IS_ALLOWED_TO_MMAP_SELF
    0x09A67B9,          // KERNEL_PATCH_MMAP_SELF_CALL_IS_LOADABLE
    0x02A66D0,          // KERNEL_PATCH_SYS_GETGID
};

uint64_t g_gadget_map_230[] = {
    0x103f7e,           // KERNEL_GADGET_RET
    0x16acb2,           // KERNEL_GADGET_INFLOOP
    0xae0030,           // KERNEL_GADGET_HYPERCALL_SET_CPUID_PS4
    0xae069f,           // KERNEL_GADGET_RETURN_ADDR
    0x1a6538,           // KERNEL_GADGET_POP_RDI
    0x13ee4e,           // KERNEL_GADGET_POP_RSI
    0x33ad4d,           // KERNEL_GADGET_POP_RDX
    0x1c3190,           // KERNEL_GADGET_POP_RAX
    0x1325f6,           // KERNEL_GADGET_POP_RBX
    0x201c59,           // KERNEL_GADGET_ADD_RAX_RDX
    0x672cb7,           // KERNEL_GADGET_MOV_R9_QWORD_PTR_RDI_48
    0x62d121,           // KERNEL_GADGET_POP_R12
    0x3b27e6,           // KERNEL_GADGET_MOV_QWORD_PTR_RDI_RSI
    0x14a127,           // KERNEL_GADGET_POP_RSP
    0x16b250,           // KERNEL_GADGET_MOV_RAX_QWORD_PTR_RAX
    0x16b3f7,           // KERNEL_GADGET_MOV_QWORD_PTR_RAX_0
    0x2485b0,           // KERNEL_GADGET_SETJMP
    0x2485e0,           // KERNEL_GADGET_LONGJMP
    0xb5d70c,           // KERNEL_GADGET_JOP1
    0x1d894f,           // KERNEL_GADGET_JOP2
};

#endif // OFFSETS_2_30_H
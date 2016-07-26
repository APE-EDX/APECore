#pragma once

#include "asm_classes.hpp"

inline void push_rcx(MemoryFunction& fn) { fn << (uint8_t)0x51; }
inline void pop_rcx(MemoryFunction& fn) { fn << (uint8_t)0x59; }

inline void push_rdx(MemoryFunction& fn) { fn << (uint8_t)0x52; }
inline void pop_rdx(MemoryFunction& fn) { fn << (uint8_t)0x5A; }

inline void push_rbx(MemoryFunction& fn) { fn << (uint8_t)0x53; }
inline void pop_rbx(MemoryFunction& fn) { fn << (uint8_t)0x5B; }

inline void push_rbp(MemoryFunction& fn) { fn << (uint8_t)0x55; }
inline void pop_rbp(MemoryFunction& fn) { fn << (uint8_t)0x5D; }

inline void push_rdi(MemoryFunction& fn) { fn << (uint8_t)0x57; }
inline void pop_rdi(MemoryFunction& fn) { fn << (uint8_t)0x5F; }

inline void push_r8(MemoryFunction& fn) { fn << (uint16_t)0x5041; }
inline void pop_r8(MemoryFunction& fn) { fn << (uint16_t)0x5841; }

inline void push_r9(MemoryFunction& fn) { fn << (uint16_t)0x5141; }
inline void pop_r9(MemoryFunction& fn) { fn << (uint16_t)0x5941; }

inline void push_r10(MemoryFunction& fn) { fn << (uint16_t)0x5241; }
inline void pop_r10(MemoryFunction& fn) { fn << (uint16_t)0x5A41; }

inline void xor_r10_r10(MemoryFunction& fn)
{
	fn << (uint8_t)0x4D;
	fn << (uint8_t)0x31;
	fn << (uint8_t)0xD2;
}

inline void mov_rdx_r8(MemoryFunction& fn)
{
	fn << (uint8_t)0x4C;
	fn << (uint8_t)0x89;
	fn << (uint8_t)0xC2;
}

inline void mov_xxx_qword_ptr_rsp(MemoryFunction& fn, uint8_t reg0, uint8_t reg, uint8_t reg2, uint8_t offset)
{
	fn << reg0;
	fn << (uint8_t)0x8B;
	fn << reg;
	fn << reg2;
	fn << offset;
}

inline void mov_rbx_qword_ptr_rsp(MemoryFunction& fn, uint8_t offset)
{
	mov_xxx_qword_ptr_rsp(fn, 0x48, 0x5C, 0x24, offset);
}

inline void mov_rcx_qword_ptr_rsp(MemoryFunction& fn, uint8_t offset)
{
	mov_xxx_qword_ptr_rsp(fn, 0x48, 0x4C, 0x24, offset);
}

inline void mov_rdx_qword_ptr_rsp(MemoryFunction& fn, uint8_t offset)
{
	mov_xxx_qword_ptr_rsp(fn, 0x48, 0x54, 0x24, offset);
}

inline void mov_r8_qword_ptr_rsp(MemoryFunction& fn, uint8_t offset)
{
	mov_xxx_qword_ptr_rsp(fn, 0x4C, 0x44, 0x24, offset);
}

inline void mov_r9_qword_ptr_rsp(MemoryFunction& fn, uint8_t offset)
{
	mov_xxx_qword_ptr_rsp(fn, 0x4C, 0x4C, 0x24, offset);
}

inline void mov_rdx_qword_ptr_rbp_rax(MemoryFunction& fn, uint8_t offset)
{
	mov_xxx_qword_ptr_rsp(fn, 0x48, 0x54, 0x05, offset);
}

inline void mov_rbp_rsp(MemoryFunction& fn)
{
	fn << (uint8_t)0x48;
	fn << (uint8_t)0x89;
	fn << (uint8_t)0xE5;
}

inline void mov_rcx_abs(MemoryFunction& fn, uint64_t val)
{
	fn << (uint16_t)0xB948;
	fn << val;
}

inline void mov_rdx_abs(MemoryFunction& fn, uint64_t val)
{
	fn << (uint16_t)0xBA48;
	fn << val;
}

inline void mov_rdx_rax(MemoryFunction& fn)
{
	fn << (uint8_t)0x48;
	fn << (uint8_t)0x89;
	fn << (uint8_t)0xC2;
}

inline void mov_r8_abs(MemoryFunction& fn, uint64_t val)
{
	fn << (uint16_t)0xB849;
	fn << val;
}

inline void mov_r10_abs(MemoryFunction& fn, uint64_t val)
{
	fn << (uint16_t)0xBA49;
	fn << val;
}

inline void mov_rax_abs(MemoryFunction& fn, uint32_t val)
{
	fn << (uint8_t)0x48;
	fn << (uint8_t)0xC7;
	fn << (uint8_t)0xC0;
	fn << val;
}

inline void mov_rax_abs(MemoryFunction& fn, uint64_t val)
{
	fn << (uint8_t)0x48;
	fn << (uint8_t)0xB8;
	fn << val;
}

inline void push_rax(MemoryFunction& fn)
{
	fn << (uint8_t)0x50;
}

inline void mov_edi_ebx(MemoryFunction& fn)
{
	fn << (uint16_t)0xDF89;
}

inline void mov_rdx_rbx(MemoryFunction& fn)
{
	fn << (uint8_t)0x48;
	fn << (uint8_t)0x89;
	fn << (uint8_t)0xDA;
}

inline void test_edi_edi(MemoryFunction& fn)
{
	fn << (uint16_t)0xFF85;
}

inline void cmp_r10_rdi(MemoryFunction& fn)
{
	fn << (uint8_t)0x49;
	fn << (uint8_t)0x39;
	fn << (uint8_t)0xFA;
}

inline void dec_edi(MemoryFunction& fn)
{
	fn << (uint16_t)0xCFFF;
}

inline void inc_r10(MemoryFunction& fn)
{
	fn << (uint8_t)0x49;
	fn << (uint8_t)0xFF;
	fn << (uint8_t)0xC2;
}

inline void sub_rsp_abs(MemoryFunction& fn, uint8_t val)
{
	fn << (uint8_t)0x48;
	fn << (uint8_t)0x83;
	fn << (uint8_t)0xEC;
	fn << val;
}
inline void add_rsp_abs(MemoryFunction& fn, uint8_t val)
{
	fn << (uint8_t)0x48;
	fn << (uint8_t)0x83;
	fn << (uint8_t)0xC4;
	fn << val;
}

inline void push(MemoryFunction& fn, uint8_t b)
{
	fn << (uint8_t)0x6A;
	fn << b;
}

template <typename T>
inline void call(MemoryFunction& fn, T callee)
{
	sub_rsp_abs(fn, 0x28);

	fn << (uint8_t)0xE8;
	fn << (uint32_t)(((uintptr_t)(void*)callee - (fn.get() - 1)) - 5);

	add_rsp_abs(fn, 0x28);
}

inline void call_rax(MemoryFunction& fn)
{
	sub_rsp_abs(fn, 0x28);
	fn << (uint16_t)0xD0FF;
	add_rsp_abs(fn, 0x28);
}

template <typename T>
inline void jmp_long(MemoryFunction& fn, T callee)
{
	fn << (uint8_t)0xE9;
	fn << (uint32_t)(((uintptr_t)(void*)callee - (fn.get() - 1)) - 5);
}

inline void je_short(MemoryFunction& fn, uint8_t dist)
{
	fn << (uint8_t)0x74;
	fn << (uint8_t)(dist - 2);
}

inline void jmp_short(MemoryFunction& fn, uint8_t dist)
{
	fn << (uint8_t)0xEB;
	fn << (uint8_t)(dist - 2);
}

inline void imul_eax_edi(MemoryFunction& fn)
{
	fn << (uint8_t)0x0F;
	fn << (uint8_t)0xAF;
	fn << (uint8_t)0xC7;
}

inline void imul_rax_r10(MemoryFunction& fn)
{
	fn << (uint8_t)0x49;
	fn << (uint8_t)0x0F;
	fn << (uint8_t)0xAF;
	fn << (uint8_t)0xC2;
}

inline void ret(MemoryFunction& fn)
{
	fn << (uint8_t)0xC3;
}

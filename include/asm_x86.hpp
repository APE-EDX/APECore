#pragma once

#include "asm_classes.hpp"

inline void push_eax(MemoryFunction& fn) { fn << (uint8_t)0x50; }
inline void push_ebx(MemoryFunction& fn) { fn << (uint8_t)0x53; }
inline void push_ebp(MemoryFunction& fn) { fn << (uint8_t)0x55; }
inline void push_ecx(MemoryFunction& fn) { fn << (uint8_t)0x51; }
inline void push_edi(MemoryFunction& fn) { fn << (uint8_t)0x57; }

inline void pop_edi(MemoryFunction& fn) { fn << (uint8_t)0x5F; }
inline void pop_ebx(MemoryFunction& fn) { fn << (uint8_t)0x5B; }
inline void pop_ecx(MemoryFunction& fn) { fn << (uint8_t)0x59; }
inline void pop_ebp(MemoryFunction& fn) { fn << (uint8_t)0x5D; }

inline void push(MemoryFunction& fn, uint8_t b)
{
	fn << (uint8_t)0x6A; 
	fn << b;
}

inline void push(MemoryFunction& fn, uint32_t address)
{
	fn << (uint8_t)0x68;
	fn << address;
}

inline void push_dword_ptr_esp(MemoryFunction& fn, uint8_t offset)
{
	fn << (uint8_t)0x36;
	fn << (uint8_t)0xFF;
	fn << (uint8_t)0x74;
	fn << (uint8_t)0x24;
	fn << offset;
}

inline void add_esp(MemoryFunction& fn, uint8_t b)
{
	fn << (uint8_t)0x83;
	fn << (uint8_t)0xC4;
	fn << (uint8_t)b;
}

inline void mov_ebx_dword_ptr_esp(MemoryFunction& fn, uint8_t offset)
{
	fn << (uint8_t)0x36;
	fn << (uint8_t)0x8B;
	fn << (uint8_t)0x5C;
	fn << (uint8_t)0x24;
	fn << offset;
}

inline void mov_eax_dword_ptr_ebp_eax(MemoryFunction& fn, uint8_t offset)
{
	fn << (uint8_t)0x36;
	fn << (uint8_t)0x8B;
	fn << (uint8_t)0x44;
	fn << (uint8_t)0x05;
	fn << offset;
}

inline void mov_ecx_dword_ptr_esp(MemoryFunction& fn, uint8_t offset)
{
	fn << (uint8_t)0x8B;
	fn << (uint8_t)0x4C;
	fn << (uint8_t)0x24;
	fn << offset;
}

inline void mov_eax_abs(MemoryFunction& fn, uint32_t val)
{
	fn << (uint8_t)0xB8;
	fn << val;
}

inline void mov_ecx_ebx(MemoryFunction& fn)
{
	fn << (uint16_t)0xCB8B;
}

inline void mov_edi_ebx(MemoryFunction& fn)
{
	fn << (uint16_t)0xFB8B;
}

inline void mov_ecx_edi(MemoryFunction& fn)
{
	fn << (uint16_t)0xCF8B;
}

inline void mov_ebp_esp(MemoryFunction& fn)
{
	fn << (uint16_t)0xEC8B;
}

inline void mov_esp_ebp(MemoryFunction& fn)
{
	fn << (uint16_t)0xE58B;
}

inline void xor_edi_edi(MemoryFunction& fn)
{
	fn << (uint16_t)0xFF33;
}

inline void test_edi_edi(MemoryFunction& fn)
{
	fn << (uint16_t)0xFF85;
}

inline void cmp_edi_ecx(MemoryFunction& fn)
{
	fn << (uint16_t)0xF93B;
}

inline void dec_edi(MemoryFunction& fn)
{
	fn << (uint8_t)0x4F;
}

inline void inc_edi(MemoryFunction& fn)
{
	fn << (uint8_t)0x47;
}

inline void call(MemoryFunction& fn, void* callee)
{
	fn << (uint8_t)0xE8;
	fn << (uint32_t)(((uintptr_t)callee - (fn.get() - 1)) - 5);
}

inline void call_eax(MemoryFunction& fn)
{
	fn << (uint16_t)0xD0FF;
}

inline void jmp_long(MemoryFunction& fn, void* callee)
{
	fn << (uint8_t)0xE9;
	fn << (uint32_t)(((uintptr_t)callee - (fn.get() - 1)) - 5);
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

inline void retn(MemoryFunction& fn, uint16_t numArgs)
{
	fn << (uint8_t)0xC2;
	fn << (uint16_t)(numArgs * 4);
}


inline void ret(MemoryFunction& fn)
{
	fn << (uint8_t)0xC3;
}

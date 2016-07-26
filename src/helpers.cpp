#include "helpers.hpp"
#include "common.hpp"
#include "apecore.hpp"

#include <string>

duk_ret_t sizeOfPtr(duk_context* ctx)
{
	duk_push_int(ctx, sizeof(uintptr_t));
	return 1;
}

duk_ret_t addressOf(duk_context *ctx)
{
    int n = duk_get_top(ctx);  /* #args */

    // Library and method
    const char* libname = duk_to_string(ctx, 0);
    const char* method = duk_to_string(ctx, 1);

	uintptr_t addr = (uintptr_t)methodAddress(libname, method);
    duk_push_pointer(ctx, (void*)addr);

    return 1;
}

duk_ret_t charCodeAt(duk_context *ctx)
{
	const char* str = duk_to_string(ctx, 0);
	int idx = duk_to_int(ctx, 1);
	duk_push_int(ctx, str[idx]);
	return 1;
}

duk_ret_t fromCharCode(duk_context *ctx)
{
	uint8_t code = (uint8_t)duk_to_int(ctx, 0);
	duk_push_lstring(ctx, (char*)&code, 1);
	return 1;
}

uintptr_t getPointer(duk_context* ctx, duk_idx_t idx)
{
	if (duk_is_pointer(ctx, idx))
	{
		return (uintptr_t)duk_to_pointer(ctx, idx);
	}

	if (duk_is_string(ctx, idx))
	{
		const char* address = duk_to_string(ctx, idx);
		return (uintptr_t)std::stoul(address, nullptr, 16);
	}

	return (uintptr_t)duk_to_int(ctx, idx);
}

duk_ret_t writeMemory(duk_context *ctx)
{
	uintptr_t address = getPointer(ctx, 0);
	uintptr_t offset = duk_to_int(ctx, 1);
	uintptr_t value = getPointer(ctx, 2);

	*(uintptr_t*)(address + offset) = value;

	duk_push_boolean(ctx, true);
	return 1;
}

duk_ret_t readMemory(duk_context *ctx)
{
	uintptr_t address = getPointer(ctx, 0);
	uintptr_t offset = duk_to_int(ctx, 1);

	duk_push_pointer(ctx, (void*)(*(uintptr_t*)(address + offset)));
	return 1;
}

duk_ret_t readString(duk_context *ctx)
{
	uintptr_t address = getPointer(ctx, 0);
	uintptr_t offset = duk_to_int(ctx, 1);

	if (duk_get_top(ctx) > 2)
	{
		uint32_t len = (uint32_t)duk_to_int(ctx, 2);
		duk_push_lstring(ctx, (char*)(address + offset), len);
	}
	else
	{
		duk_push_string(ctx, (char*)(address + offset));
	}

	return 1;
}

duk_ret_t sigScan(duk_context* ctx)
{
	const char* str = duk_to_string(ctx, 0);
	size_t len = strlen(str);

	bool skipNonExecutable = true;
	if (duk_get_top(ctx) > 1)
	{
		skipNonExecutable = duk_to_boolean(ctx, 1);
	}

	// Convert str to a) hex, b) mask
	size_t nbytes = len / 2;
	bool* mask = new bool[len];
	uint8_t* hex = new uint8_t[nbytes];
	
	bool pair = true;
	for (size_t i = 0; i < len; ++i, pair = !pair)
	{
		if (str[i] >= '0' && str[i] <= '9')
		{
			mask[i] = true;
			hex[(int)(i / 2)] = pair ? ((uint8_t)(str[i] - '0') << 4) : (hex[(int)(i / 2)] | (uint8_t)(str[i] - '0'));
		}
		else if (str[i] >= 'a' && str[i] <= 'f')
		{
			mask[i] = true;
			hex[(int)(i / 2)] = pair ? ((uint8_t)(str[i] - 'a' + 0xA) << 4) : (hex[(int)(i / 2)] | (uint8_t)(str[i] - 'a' + 0xA));
		}
		else if (str[i] >= 'A' && str[i] <= 'F')
		{
			mask[i] = true;
			hex[(int)(i / 2)] = pair ? ((uint8_t)(str[i] - 'A' + 0xA) << 4) : (hex[(int)(i / 2)] | (uint8_t)(str[i] - 'A' + 0xA));
		}
		else
		{
			mask[i] = false;
		}
	}

	uintptr_t foundAddress = 0;
	uintptr_t baseAddress = (uintptr_t)getProcessOEP();
	uint32_t moduleSize = getProcessSize();
	uintptr_t finalAddress = baseAddress + moduleSize;
	uintptr_t EOR;
	uint8_t x;

	for (uintptr_t currentAddress = baseAddress; currentAddress < finalAddress && foundAddress == 0; ++currentAddress)
	{
		size_t size;
		MemoryProtect protect = virtualMemoryProtectState((void*)currentAddress, &size);
		if (protect != MemoryProtect::EXECUTE_READWRITE && protect != MemoryProtect::EXECUTE_READ)
		{
			if (skipNonExecutable || (protect != MemoryProtect::READ && protect != MemoryProtect::READWRITE))
			{
				currentAddress += size;
				continue;
			}
		}

		// TODO: Use a better algorithm, something like 
		EOR = currentAddress + size - nbytes;
		for (; currentAddress < EOR; ++currentAddress)
		{
			for (x = 0; x < nbytes; x++)
			{
				uint8_t hb = hex[x];
				uint8_t cb = *(uint8_t*)(currentAddress + x);

				if (((hb & 0xF0) != (cb & 0xF0)) && mask[x * 2])
				{
					break;
				}

				if (((hb & 0x0F) != (cb & 0x0F)) && mask[x * 2 + 1])
				{
					break;
				}
			}

			if (x == nbytes)
			{
				foundAddress = currentAddress;
				break;
			}
		}
	}

	duk_push_pointer(ctx, (void*)foundAddress);
	return 1;
}

/*
duk_push_external_buffer(ctx);
duk_config_buffer(ctx, -1, p, len);
*/

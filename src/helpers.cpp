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

/*
duk_push_external_buffer(ctx);
duk_config_buffer(ctx, -1, p, len);
*/

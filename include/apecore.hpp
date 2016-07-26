#pragma once

#include <duktape.h>

typedef void(*ExtendedInit)(duk_context*);

duk_context* apecore_initialize(ExtendedInit);
duk_context* apecore_createHeap(ExtendedInit);
int apecore_deinitialize();


// Interface enums
enum class VirtualState
{
    FREE,
    RESERVED
};
enum class MemoryProtect
{
    READ,
    READWRITE,
    EXECUTE,
	EXECUTE_READ,
    EXECUTE_READWRITE
};

// Interface types
typedef void*(*ThreadFunction)(void*);

// Platform specific external functions
extern bool createThread(ThreadFunction, void* parameter);

extern size_t getLibraryPath(char* buffer, size_t size);
extern void* getLibraryOEP();
extern uint32_t getLibrarySize();

extern VirtualState virtualMemoryState(void* address);
extern void* virtualMemoryCommit(void* address, size_t size, MemoryProtect protect);
extern bool virtualMemoryProtect(void* address, size_t size, MemoryProtect protect, MemoryProtect* old);

extern void* methodAddress(const char* library, const char* method);

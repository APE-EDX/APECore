#pragma once

#include <duktape.h>

duk_context* initialize();
duk_context* createHeap();
int deinitialize();


// Interface enums
enum class VirtualState
{
    MEM_FREE,
    MEM_RESERVED
};
enum class MemoryProtect
{
    READ,
    WRITE,
    READWRITE,
    EXECUTE,
    EXECUTE_READWRITE
};

// Interface types
typedef void*(*ThreadFunction)(void*);

// Platform specific external functions
extern bool createThread(ThreadFunction, void* parameter);

extern size_t getLibraryPath(char* buffer, size_t size);
extern void* getLibraryOEP();
extern void* getLibrarySize();

extern VirtualState virtualMemoryState(void* address);
extern void* virtualMemoryCommit(void* address, size_t size, MemoryProtect protect);
extern void* virtualMemoryProtect(void* address, size_t size, MemoryProtect protect, MemoryProtect* old);

extern void* methodAddress(const char* library, const char* method);

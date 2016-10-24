#pragma once

#include <duktape.h>


#ifdef _WIN32
    #define SEPARATOR_STR "\\"
    #define SEPARATOR_CHR '\\'
#else
    #define SEPARATOR_STR "/"
    #define SEPARATOR_CHR '/'
#endif


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
	NONE,
    READ,
    READWRITE,
    EXECUTE,
	EXECUTE_READ,
    EXECUTE_READWRITE
};

// Interface types
typedef void*(*ThreadFunction)(void*);

namespace ape
{
    namespace platform
    {
        // Platform specific external functions
        extern void sleep(uint32_t ms);
        extern bool createThread(ThreadFunction, void* parameter);

        extern size_t getLibraryPath(char* buffer, size_t size);
        extern void* getLibraryOEP();
        extern uint32_t getLibrarySize();

        extern void* getProcessOEP();
        extern uint32_t getProcessSize();

        extern VirtualState virtualMemoryState(void* address, size_t* size = nullptr);
        extern MemoryProtect virtualMemoryProtectState(void* address, size_t* size = nullptr);
        extern void* virtualMemoryCommit(void* address, size_t size, MemoryProtect protect);
        extern bool virtualMemoryProtect(void* address, size_t size, MemoryProtect protect, MemoryProtect* old);

        extern void* methodAddress(const char* library, const char* method);
    }
}

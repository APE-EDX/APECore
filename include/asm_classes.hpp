#pragma once

#include "apecore.hpp"

#include <inttypes.h>

class Allocator
{
public:
        Allocator() :
                _lastMemory(NULL),
                _remainingSize(0)
        {}

        void* GetNearMemory(void* address, size_t size)
        {
                uintptr_t mem = NULL;

                if (size < _remainingSize && _lastMemory != NULL)
                {
                        mem = _lastMemory;
                        increase(size);
                }
                else
                {
						if (address == NULL)
						{
							address = (void*)((uintptr_t)ape::platform::getLibraryOEP() + (uintptr_t)ape::platform::getLibrarySize());
						}

                        for (int i = 0; i < 20; ++i)
                        {
							address = (void*)((uintptr_t)address + i * 0x10000);
							VirtualState state = ape::platform::virtualMemoryState(address);

							if (state == VirtualState::FREE)
							{
								mem = (uintptr_t)ape::platform::virtualMemoryCommit(address, 0x10000, MemoryProtect::EXECUTE_READWRITE);
								if (mem)
								{
									_lastMemory = mem + size;
									_remainingSize = 0x10000 - size;
									break;
								}
							}
                        }
                }

                return (void*)mem;
        }

        void increase(size_t size)
        {
                _lastMemory += size;
                _remainingSize -= size;
        }

private:
        uintptr_t _lastMemory;
        size_t _remainingSize;
};

class MemoryFunction
{
public:
	MemoryFunction(Allocator* allocator, size_t size) :
		_allocator(allocator),
		_allocated(0),
		_total(size),
		_resizeAmount(1)
	{
		_memStart = _mem = (uintptr_t)allocator->GetNearMemory(NULL, size);
	}

	void increase(uint16_t minSize)
	{
		while (_resizeAmount < minSize)
		{
			_resizeAmount *= 2;
		}

		_allocator->increase(_resizeAmount);
		_total += _resizeAmount;

		if (_resizeAmount < 32)
		{
			_resizeAmount *= 2;
		}
	}

	template <typename T>
	inline void operator<<(T b)
	{
		if (_allocated + sizeof(T) > _total)
		{
			increase(sizeof(T));
		}

		*(T*)_mem = b;
		_mem += sizeof(T);
		_allocated += sizeof(T);

	}

	inline intptr_t get()
	{
		return _mem;
	}

	inline void* start()
	{
		return (void*)_memStart;
	}

private:
	Allocator* _allocator;
	uintptr_t _mem;
	uintptr_t _memStart;
	uint16_t _allocated;
	uint16_t _total;
	uint16_t _resizeAmount;
};

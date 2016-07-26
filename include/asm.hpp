#pragma once

#ifdef BUILD_64
	#include "asm_x64.hpp"
#else
	#include "asm_x86.hpp"
#endif

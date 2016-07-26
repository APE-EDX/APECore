#pragma once

#include <duktape.h>

enum class CallConvention
{
    STDCALL,
    CDECLCALL,
    FASTCALL
};

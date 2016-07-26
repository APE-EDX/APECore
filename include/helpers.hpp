#pragma once

#include <inttypes.h>
#include <duktape.h>

duk_ret_t sizeOfPtr(duk_context* ctx);
duk_ret_t addressOf(duk_context *ctx);
duk_ret_t charCodeAt(duk_context *ctx);
duk_ret_t fromCharCode(duk_context *ctx);

duk_ret_t writeMemory(duk_context *ctx);
duk_ret_t readMemory(duk_context *ctx);
duk_ret_t readString(duk_context *ctx);

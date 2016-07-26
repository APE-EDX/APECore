#include "socket.hpp"

#include <duktape.h>
#include <capstone.h>
#include <vector>

#include "apecore.hpp"
#include "helpers.hpp"
#include "redirect.hpp"

ClientSocket* clientSocket = nullptr;
duk_context* initialCtx;
char apiPath[256] = { 0 };
char* apiOverride = nullptr;
bool hasApiPath = false;

csh capstoneHandle;


void require(duk_context* ctx, char* base_path, char* override_path, const char* file)
{
    // Override with the API file
    strcpy(override_path, file);

    // Load it to duktape
    duk_push_object(ctx);
    duk_eval_file(ctx, base_path);
}

struct ThreadData
{
	ClientSocket* clientSocket;
	duk_context* ctx;
};

static void socketRecv(ThreadData* threadData)
{
    duk_idx_t thr_idx;
    duk_context *new_ctx;

    thr_idx = duk_push_thread(threadData->ctx);
    new_ctx = duk_get_context(threadData->ctx, thr_idx);

	std::string oldBuffer = "";
	uint16_t currentLen = -1;
	bool isNew = true;
    while (1)
    {
        std::string buffer = threadData->clientSocket->recv();
		oldBuffer += buffer;

		while (oldBuffer.length() >= 2)
		{
			if (isNew)
			{
				currentLen = (uint16_t)(((uint16_t)(uint8_t)oldBuffer[1] << 8) | (uint8_t)oldBuffer[0]);
				isNew = false;
			}

			if (oldBuffer.length() >= currentLen + 2)
			{
				duk_push_global_object(new_ctx);
				duk_get_prop_string(new_ctx, -1, "onMessage");
				duk_push_string(new_ctx, oldBuffer.substr(2, currentLen).c_str());
				duk_pcall(new_ctx, 1);

				// Reset
				oldBuffer = oldBuffer.substr(currentLen + 2);
				currentLen = -1;
				isNew = true;
			}
			else
			{
				break;
			}
		}
    }

	delete threadData;
}

duk_context* apecore_initialize(ExtendedInit ext)
{
    // Create socket
    clientSocket = new ClientSocket(AF_INET, SOCK_STREAM, 0);
    clientSocket->connect("127.0.0.1", 25100);

	// Get current path
	{
		size_t len = getLibraryPath(apiPath, sizeof(apiPath));

		// Find last / and
		while (len > 0 && apiPath[--len] != '\\') {};

		// Overwrite path from here on
		apiOverride = &apiPath[len + 1];
		hasApiPath = len > 0;
	}

	duk_context* ctx = apecore_createHeap(ext);
	initialCtx = ctx;

	// Initialize capstone
#ifdef BUILD_64
	cs_mode mode = CS_MODE_64;
#else
	cs_mode mode = CS_MODE_32;
#endif
	if (cs_open(CS_ARCH_X86, mode, &capstoneHandle) != CS_ERR_OK)
	{
		// Notify of the error
	}

	// Custom user init code
	require(ctx, apiPath, apiOverride, "../../init.js");

    if (clientSocket->lastError() != SocketError::NONE)
    {
        printf("ERROR SOCKET %d\n", (int)clientSocket->lastError());
    }
    else
    {
		createThread((ThreadFunction)socketRecv, new ThreadData{ clientSocket, ctx });
    }

    return ctx;
}

duk_context* apecore_createHeap(ExtendedInit ext)
{
    duk_context* ctx = duk_create_heap_default();

    // Allow setHook to be called from inside JS
	InitializeDuktape_Redirect(ctx);

	duk_push_c_function(ctx, sizeOfPtr, 0);
	duk_put_global_string(ctx, "ptrSize");

    duk_push_c_function(ctx, addressOf, DUK_VARARGS);
    duk_put_global_string(ctx, "cpp_addressOf");

	duk_push_c_function(ctx, charCodeAt, DUK_VARARGS);
	duk_put_global_string(ctx, "cpp_charCodeAt");

	duk_push_c_function(ctx, fromCharCode, DUK_VARARGS);
	duk_put_global_string(ctx, "cpp_fromCharCode");

	duk_push_c_function(ctx, writeMemory, DUK_VARARGS);
	duk_put_global_string(ctx, "cpp_writeMemory");

	duk_push_c_function(ctx, readMemory, DUK_VARARGS);
	duk_put_global_string(ctx, "cpp_readMemory");

	duk_push_c_function(ctx, readString, DUK_VARARGS);
	duk_put_global_string(ctx, "cpp_readString");

    if (hasApiPath)
    {
        // Add all API files
        require(ctx, apiPath, apiOverride, "../../jsAPI/eval_js.js");
        require(ctx, apiPath, apiOverride, "../../jsAPI/call_convention.js");
        require(ctx, apiPath, apiOverride, "../../jsAPI/ptr.js");
        require(ctx, apiPath, apiOverride, "../../jsAPI/find.js");
        require(ctx, apiPath, apiOverride, "../../jsAPI/redirect.js");

		// Call callback
		if (ext)
		{
			(*ext)(ctx);
		}
    }
    else
    {
        // Notify of error via protocol
    }

    return ctx;
}

int apecore_deinitialize()
{
    duk_destroy_heap(initialCtx);
    return 1;
}

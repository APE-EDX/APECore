#include "socket.hpp"

#include <duktape.h>
#include <vector>

#include "apecore.hpp"
#include "helpers.hpp"
#include "redirect.hpp"

duk_context *ctx = nullptr;
ClientSocket* clientSocket = nullptr;


void require(duk_context* ctx, char* base_path, char* override_path, const char* file)
{
    // Override with the API file
    strcpy(override_path, file);

    // Load it to duktape
    duk_push_object(ctx);
    duk_eval_file(ctx, base_path);
}

static void socketRecv(ClientSocket* clientSocket)
{
    duk_idx_t thr_idx;
    duk_context *new_ctx;

    thr_idx = duk_push_thread(ctx);
    new_ctx = duk_get_context(ctx, thr_idx);

	std::string oldBuffer = "";
	uint16_t currentLen = -1;
	bool isNew = true;
    while (1)
    {
        std::string buffer = clientSocket->recv();
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
}

duk_context* initialize()
{
    // Create socket
    clientSocket = new ClientSocket(AF_INET, SOCK_STREAM, 0);
    clientSocket->connect("127.0.0.1", 25100);

    if (clientSocket->lastError() != SocketError::NONE)
    {
        printf("ERROR SOCKET %d\n", (int)clientSocket->lastError());
    }
    else
    {
        createThread((ThreadFunction)socketRecv, clientSocket);
    }

    // TODO: Remove ctx from global scope
    ctx = createHeap();

    return ctx;
}

duk_context* createHeap()
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

    // Get current path
    char path[256];
    size_t len = getLibraryPath(path, sizeof(path));

    // Find last / and
    while (len > 0 && path[--len] != '\\') {};
    if (len > 0)
    {
        // Overwrite path from here on
        char* override_from = &path[len + 1];

        // Add all API files
        require(ctx, path, override_from, "../../jsAPI/eval_js.js");
        require(ctx, path, override_from, "../../jsAPI/call_convention.js");
        require(ctx, path, override_from, "../../jsAPI/ptr.js");
        require(ctx, path, override_from, "../../jsAPI/find.js");
        require(ctx, path, override_from, "../../jsAPI/redirect.js");

        // Custom user init code
        require(ctx, path, override_from, "../../init.js");
    }
    else
    {
        // Notify of error via protocol
    }

    return ctx;
}

int deinitialize()
{
    duk_destroy_heap(ctx);

    return 1;
}

#pragma once

#include "apecore.hpp"

#include <stdlib.h>
#include <stdio.h>


class Logger
{
public:
    static Logger* global()
    {
        if (!_gLogger)
        {
            _gLogger = new Logger(true, false);
        }

        return _gLogger;
    }

    Logger(bool writeToFile, bool writeToConsole) :
        _fp(nullptr),
        _writeToFile(writeToFile),
        _writeToConsole(writeToConsole)
    {
        if (writeToFile)
        {
            // Get current path
            char path[256] = {0};

        	{
        		size_t len = ape::platform::getLibraryPath(path, sizeof(path));

        		// Find last / and
        		while (len > 0 && path[--len] != SEPARATOR_CHR) {};

        		// Overwrite path from here on
                strcpy(&path[len + 1], "apelog.txt");
        	}

            // Open file
            _fp = fopen(path, "w+");
        }
    }

    ~Logger()
    {
        if (_fp)
        {
            fclose(_fp);
        }
    }

    template <typename... Args>
    void log(char* fmt, Args... args)
    {
        if (_writeToFile)
        {
            fprintf(_fp, fmt, args...);
        }

        if (_writeToConsole)
        {
            printf(fmt, args...);
        }
    }

private:
    static Logger* _gLogger;

    FILE* _fp;
    bool _writeToFile;
    bool _writeToConsole;
};

#define gLogger Logger::global()

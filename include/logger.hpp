#pragma once

#include <stdlib.h>
#include <stdio.h>


class Logger
{
public:
    Logger(bool writeToFile, bool writeToConsole) :
        _fp(nullptr),
        _writeToFile(writeToFile),
        _writeToConsole(writeToConsole)
    {
        if (writeToFile)
        {
            // TODO(gpascualg): Is this correct?
            char path[256] = {0};
            getLibraryPath(path, 256);
            path = strcat(path, "apelog.txt");

            _fp = fopen(path, 'w+');
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
    FILE* _fp;
    bool _writeToFile;
    bool _writeToConsole;
}

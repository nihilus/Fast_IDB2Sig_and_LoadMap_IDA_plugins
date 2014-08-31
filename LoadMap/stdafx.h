// stdafx.h : include file for standard system include files,
// or project specific include files that are used frequently, but
// are changed infrequently
//

#pragma once

#define WIN32_LEAN_AND_MEAN		// Exclude rarely-used stuff from Windows headers
#include <windows.h>

// C RTL Debug Support Header Files
#include <crtdbg.h>

// Shell Lightweight API
#include <shlwapi.h>
#pragma comment(lib, "shlwapi.lib")

// IDA SDK Header Files
#include <ida.hpp>
#include <idp.hpp>
#include <loader.hpp>
#include <bytes.hpp>
#include <name.hpp>
#include <entry.hpp>
#include <fpro.h>

#ifdef _DEBUG
    #define _VERIFY(x)  _ASSERTE(x)

    #define WIN32CHECK(x)   { \
        DWORD __dwErr__ = GetLastError(); \
        _ASSERTE(x); \
        SetLastError(__dwErr__); \
    };
#else
    #define _VERIFY(x)  (x)
    #define WIN32CHECK(x)   (x)
#endif


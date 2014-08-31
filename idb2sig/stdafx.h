// stdafx.h : include file for standard system include files,
// or project specific include files that are used frequently, but
// are changed infrequently
//

#pragma once

#define WIN32_LEAN_AND_MEAN		// Exclude rarely-used stuff from Windows headers

// Windows Header Files:
#include <windows.h>

// CRTL Debugging support header file
#include <crtdbg.h>

// Shell Lightweight API Header File
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

// STL Header Files
#pragma warning(disable: 4702)

#include <map>
#include <vector>

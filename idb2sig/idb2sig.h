#ifndef __IDB2SIG_H__
#define __IDB2SIG_H__

#pragma once

#define DOT             0x2E
#define SPACE           0x20
#define ONE_MB          (1024 * 1024)

#define countof(x)      (sizeof(x) / sizeof((x)[0]))

#define DEF_REVERSE_SIZE    10
#define DEF_MIN_FUNC_LENGTH 6

#ifdef _DEBUG
    #define _VERIFY(x) _ASSERTE(x)
#else
    #define _VERIFY(x) (x)
#endif

typedef enum tagFUNCTION_MODE {
    FUNCTION_MODE_MIN = 0,
    NON_AUTO_FUNCTIONS = FUNCTION_MODE_MIN, // non auto-generated functions
    LIBRARY_FUNCTIONS,                      // library functions
    PUBLIC_FUNCTIONS,                       // public functions
    ENTRY_POINT_FUNCTIONS,                  // entry point function
    ALL_FUNCTIONS,                          // all functions
    USER_SELECT_FUNCTION,                   // any current or user selects function
    FUNCTION_MODE_MAX = USER_SELECT_FUNCTION
} FUNCTION_MODE;

struct PLUGIN_OPTIONS
{
    FUNCTION_MODE funcMode;
    bool bPatAppend;
    bool bConfirm;
    ulong ulMinFuncLen;
    ulong ulReverseSize;

    PLUGIN_OPTIONS()
    {
        funcMode = FUNCTION_MODE_MIN;
        bPatAppend = false;
        bConfirm = true;
        ulMinFuncLen = NON_AUTO_FUNCTIONS;
        ulReverseSize = DEF_REVERSE_SIZE;
    }
};

#endif  // __IDB2SIG_H__

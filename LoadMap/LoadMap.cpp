////////////////////////////////////////////////////////////////////////////////
/**
 * @file LoadMap.cpp
 * The main implementation file
 * @author TQN (truong_quoc_ngan@yahoo.com)
 * @date 09/11/2004
 * An IDA plugin, which loads a VC/Borland/Dede map file into IDA 4.5
 * Base on the idea of loadmap plugin of Toshiyuki Tega
 * Ver:    1.0 - 09/11/2004 - Initial release
 */
////////////////////////////////////////////////////////////////////////////////

#include "stdafx.h"

typedef struct _tagPLUGIN_OPTIONS {
    bool bNameApply;    // true - apply to name, false - apply to comment
    bool bReplace;      // replace the existing name or comment
    bool bVerbose;      // show detail messages
} PLUGIN_OPTIONS;

typedef enum _tagMAP_OPEN_ERROR {
    OPEN_NO_ERROR = 0,
    WIN32_ERROR,
    FILE_EMPTY_ERROR,
    FILE_BINARY_ERROR
} MAP_OPEN_ERROR;

// This is where the symbol table starts, do not edit.
const char VC_HDR_START[]       = "Address         Publics by Value              Rva+Base     Lib:Object";
const char BL_HDR_NAME_START[]  = "Address         Publics by Name";
const char BL_HDR_VALUE_START[] = "Address         Publics by Value";

const size_t g_minLineLen = 14; // For a "xxxx:xxxxxxxx " line

static HINSTANCE g_hinstPlugin = NULL;
static char g_szIniPath[MAX_PATH] = { 0 };

/* Global variable for options of plugin */
static PLUGIN_OPTIONS g_options = { 0 };

/* Ini Section and Key names */
static char g_szLoadMapSection[] = "LoadMap";
static char g_szOptionsKey[] = "Options";

////////////////////////////////////////////////////////////////////////////////
/// global inline static  SkipSpaces
/// @brief Seek to non space character at the beginning of a memory buffer
/// @param  lpStart LPSTR   Pointer to start of buffer
/// @param  lpEnd LPSTR Pointer to end of buffer
/// @return LPSTR Pointer to first non space character at the beginning of buffer
/// @author TQN
/// @date 09/11/2004
////////////////////////////////////////////////////////////////////////////////
static inline LPSTR SkipSpaces(LPCSTR pStart, LPCSTR pEnd)
{
    _ASSERTE(pStart != NULL);
    _ASSERTE(pEnd != NULL);
    _ASSERTE(pStart <= pEnd);

    LPCSTR p = pStart;
    while ((p < pEnd) && isspace(*p))
    {
        p++;
    }

    return (LPSTR) p;
}

////////////////////////////////////////////////////////////////////////////////
/// global inline static  FindEOLChar
/// @brief Find the EOL character '\r' or '\n' in a memory buffer
/// @param  lpStart LPSTR Pointer to start of buffer
/// @param  lpEnd LPSTR Pointer to end of buffer
/// @return LPSTR Pointer to first EOL character in the buffer
/// @author TQN
/// @date 09/12/2004
////////////////////////////////////////////////////////////////////////////////
static inline LPSTR FindEOL(LPCSTR pStart, LPCSTR pEnd)
{
    _ASSERTE(pStart != NULL);
    _ASSERTE(pEnd != NULL);
    _ASSERTE(pStart <= pEnd);

    LPCSTR p = pStart;
    while ((p < pEnd) && ('\r' != *p) && ('\n' != *p))
    {
        p++;
    }

    return (LPSTR) p;
}

////////////////////////////////////////////////////////////////////////////////
/// global static  ShowMsg
/// @brief Output a formatted string to messages window [analog of printf()]
/// only when the verbose flag of plugin's options is true
/// @param  format const char * printf() style message string.
/// @return void
/// @author TQN
/// @date 09/11/2004
////////////////////////////////////////////////////////////////////////////////
static void ShowMsg(const char *format, ...)
{
    if (g_options.bVerbose)
    {
        va_list va;
        va_start(va, format);
        (void) vmsg(format, va);
        va_end(va);
    }
}

////////////////////////////////////////////////////////////////////////////////
/**
 * @brief Open a map file and map the file content to virtual memory
 * @param lpszFileName  Path name of file to open.
 * @param dwSize Out variable to receive size of file.
 * @param lpMapAddr The pointer to memory address of mapped file
 * @return enum value of OPEN_FILE_ERROR
 * @author TQN
 * @date 09/12/2004
 */
////////////////////////////////////////////////////////////////////////////////
static MAP_OPEN_ERROR MapFileOpen(IN LPCSTR lpszFileName,
                                  OUT LPSTR &lpMapAddr,
                                  OUT DWORD &dwSize)
{
    // Set default values for output parameters
    lpMapAddr = NULL;
    dwSize = INVALID_FILE_SIZE;

    // Validate all input pointer parameters
    _ASSERTE(NULL != lpszFileName);
    _ASSERTE(FALSE == IsBadStringPtr(lpszFileName, (UINT_PTR) -1));
    if ((NULL == lpszFileName) || IsBadStringPtr(lpszFileName, (UINT_PTR) -1))
    {
        SetLastError(ERROR_INVALID_PARAMETER);
        return WIN32_ERROR;
    }

    // Open the file
    HANDLE hFile = CreateFile(lpszFileName, GENERIC_READ, FILE_SHARE_READ, NULL,
                              OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (INVALID_HANDLE_VALUE == hFile)
    {
        return WIN32_ERROR;
    }

    dwSize = GetFileSize(hFile, NULL);
    if ((INVALID_FILE_SIZE == dwSize) || (0 == dwSize))
    {
        // File too large or empty
        WIN32CHECK(CloseHandle(hFile));
        return ((0 == dwSize) ? FILE_EMPTY_ERROR : WIN32_ERROR);
    }

    HANDLE hMap = CreateFileMapping(hFile, NULL, PAGE_READONLY, 0, 0, NULL);
    if (NULL == hMap)
    {
        WIN32CHECK(CloseHandle(hFile));
        return WIN32_ERROR;
    }

    // Mapping creation successful, do not need file handle anymore
    WIN32CHECK(CloseHandle(hFile));

    lpMapAddr = (LPSTR) MapViewOfFile(hMap, FILE_MAP_READ, 0, 0, dwSize);
    if (NULL == lpMapAddr)
    {
        WIN32CHECK(CloseHandle(hMap));
        return WIN32_ERROR;
    }

    // Map View successful, do not need the map handle anymore
    WIN32CHECK(CloseHandle(hMap));

    if (NULL != memchr(lpMapAddr, 0, dwSize))
    {
        // File is binary or Unicode file
        WIN32CHECK(UnmapViewOfFile(lpMapAddr));
        lpMapAddr = NULL;
        return FILE_BINARY_ERROR;
    }

    return OPEN_NO_ERROR;
}

////////////////////////////////////////////////////////////////////////////////
/**
 * @brief Close memory map file which opened by MemMapFileOpen function.
 * @param lpAddr: Pointer to memory return by MemMapFileOpen.
 * @author TQN
 * @date 09/12/2004
 */
////////////////////////////////////////////////////////////////////////////////
static void MapFileClose(IN LPCVOID lpAddr)
{
    WIN32CHECK(UnmapViewOfFile(lpAddr));
}

/* The DLL entry point of plugin */
BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID)
{
    if (DLL_PROCESS_ATTACH == fdwReason)
    {
        WIN32CHECK(DisableThreadLibraryCalls(g_hinstPlugin = hinstDLL));
    }

    return TRUE;
}

////////////////////////////////////////////////////////////////////////////////
/// global static  ShowOptionsDlg
/// Show options dialog for getting user desired options
/// @return void
/// @author TQN
/// @date 09/11/2004
////////////////////////////////////////////////////////////////////////////////
static void ShowOptionsDlg(void)
{
    // Build the format string constant used to create the dialog
    const char format[] =
        "STARTITEM 0\n"                             // TabStop
        "LoadMap Options\n"                         // Title
        "<Apply Map Symbols for Name:R>\n"          // Radio Button 0
        "<Apply Map Symbols for Comment:R>>\n"    // Radio Button 1
        "<Replace Existing Names/Comments:C>>\n"  // Checkbox Button
        "<Show verbose messages:C>>\n\n";           // Checkbox Button

    // Create the option dialog.
    short name = (g_options.bNameApply ? 0 : 1);
    short replace = (g_options.bReplace ? 1 : 0);
    short verbose = (g_options.bVerbose ? 1 : 0);
    if (AskUsingForm_c(format, &name, &replace, &verbose))
    {
        g_options.bNameApply = (0 == name);
        g_options.bReplace = (1 == replace);
        g_options.bVerbose = (1 == verbose);
    }
}

////////////////////////////////////////////////////////////////////////////////
/**
 * global static init
 * @brief Plugin initialize function
 * @return PLUGIN_KEEP always
 * @author TQN
 * @date 09/11/2004
 */
////////////////////////////////////////////////////////////////////////////////
static int idaapi init(void)
{
    msg("\nLoadMap: Plugin init.\n\n");

    // Get the full path of plugin
    WIN32CHECK(GetModuleFileName(g_hinstPlugin, g_szIniPath, sizeof(g_szIniPath)));
    g_szIniPath[sizeof(g_szIniPath) - 1] = '\0';

    // Change the extension of plugin to '.ini'
    _VERIFY(PathRenameExtension(g_szIniPath, ".ini"));

    // Get options saved in ini file
    _VERIFY(GetPrivateProfileStruct(g_szLoadMapSection, g_szOptionsKey,
                                    &g_options, sizeof(g_options), g_szIniPath));

    return PLUGIN_KEEP;
}

////////////////////////////////////////////////////////////////////////////////
/**
 * global static  run
 * @brief Plugin run function
 * @param   int    Don't used
 * @return void
 * @author TQN
 * @date 09/11/2004
 */
////////////////////////////////////////////////////////////////////////////////
static void idaapi run(int /* arg */)
{
    static char mapFileName[_MAX_PATH] = { 0 };

    // If user press shift key, show options dialog
    if (GetAsyncKeyState(VK_SHIFT) & 0x8000)
    {
        ShowOptionsDlg();
    }

    ulong numOfSegs = (ulong) get_segm_qty();
    if (0 == numOfSegs)
    {
        warning("Not found any segments");
        return;
    }

    if ('\0' == mapFileName[0])
    {
        // First run
        strncpy(mapFileName, get_input_file_path(), sizeof(mapFileName));
        WIN32CHECK(PathRenameExtension(mapFileName, ".map"));
    }

    // Show open map file dialog
    char *fname = askfile_c(0, mapFileName, "Open MAP file");
    if (NULL == fname)
    {
        msg("LoadMap: User cancel\n");
        return;
    }

    // Open the map file
    LPSTR pMapStart = NULL;
    DWORD mapSize = INVALID_FILE_SIZE;
    MAP_OPEN_ERROR eRet = MapFileOpen(fname, pMapStart, mapSize);
    switch (eRet)
    {
        case WIN32_ERROR:
            warning("Could not open file '%s'.\nWin32 Error Code = 0x%08X",
                    fname, GetLastError());
            return;

        case FILE_EMPTY_ERROR:
            warning("File '%s' is empty, zero size", fname);
            return;

        case FILE_BINARY_ERROR:
            warning("File '%s' seem to be a binary or Unicode file", fname);
            return;

        case OPEN_NO_ERROR:
        default:
            break;
    }

    bool foundHdr = false;
    ulong validSyms = 0;
    ulong invalidSyms = 0;

    // The mark pointer to the end of memory map file
    // all below code must not read or write at and over it
    LPSTR pMapEnd = pMapStart + mapSize;

    show_wait_box("Parsing and applying symbols from the Map file '%s'", fname);

    __try
    {
        LPSTR pLine = pMapStart;
        LPSTR pEOL = pMapStart;
        while (pLine < pMapEnd)
        {
            // Skip the spaces, '\r', '\n' characters, blank lines, seek to the
            // non space character at the beginning of a non blank line
            pLine = SkipSpaces(pEOL, pMapEnd);

            // Find the EOL '\r' or '\n' characters
            pEOL = FindEOL(pLine, pMapEnd);

            size_t lineLen = (size_t) (pEOL - pLine);
            if (lineLen < g_minLineLen)
            {
                continue;
            }

            if (!foundHdr)
            {
                if ((0 == strnicmp(pLine, VC_HDR_START      , lineLen)) ||
                    (0 == strnicmp(pLine, BL_HDR_NAME_START , lineLen)) ||
                    (0 == strnicmp(pLine, BL_HDR_VALUE_START, lineLen)))
                {
                    foundHdr = true;
                }
            }
            else
            {
                ulong seg = SREG_NUM;
                ulong addr = BADADDR;
                char name[MAXNAMELEN + 1];
                char fmt[80];

                name[0] = '\0';
                fmt[0] = '\0';

                // Get segment number, address, name, by pass spaces at beginning,
                // between ':' character, between address and name
                int ret = _snscanf(pLine, min(lineLen, MAXNAMELEN + g_minLineLen),
                                   " %04X : %08X %s", &seg, &addr, name);
                if (3 != ret)
                {
                    // we have parsed to end of value/name symbols table or reached EOF
                    _snprintf(fmt, sizeof(fmt), "Parsing finished at line: '%%.%ds'.\n", lineLen);
                    ShowMsg(fmt, pLine);
                    break;
                }
                else if ((0 == seg) || (--seg >= numOfSegs) ||
                        (BADADDR == addr) || ('\0' == name[0]))
                {
                    sprintf(fmt, "Invalid map line: %%.%ds.\n", lineLen);
                    ShowMsg(fmt, pLine);

                    invalidSyms++;
                }
                else
                {
                    // Ensure name is NULL terminated
                    name[MAXNAMELEN] = '\0';

                    // Determine the DeDe map file
                    bool bNameApply = g_options.bNameApply;
                    char *pname = name;
                    if (('<' == pname[0]) && ('-' == pname[1]))
                    {
                        // Functions indicator symbol of DeDe map
                        pname += 2;
                        bNameApply = true;
                    }
                    else if ('*' == pname[0])
                    {
                        // VCL controls indicator symbol of DeDe map
                        pname++;
                        bNameApply = false;
                    }
                    else if (('-' == pname[0]) && ('>' == pname[1]))
                    {
                        // VCL methods indicator symbol of DeDe map
                        pname += 2;
                        bNameApply = false;
                    }

                    ulong la = addr + getnseg((int) seg)->startEA;
                    flags_t f = getFlags(la);

                    if (bNameApply) // Apply symbols for name
                    {
                        //  Add name if there's no meaningful name assigned.
                        if (g_options.bReplace ||
                            (!has_name(f) || has_dummy_name(f) || has_auto_name(f)))
                        {
                            if (set_name(la, pname, SN_NOWARN))
                            {
                                ShowMsg("%04X:%08X - Change name to '%s' successed\n",
                                        seg, la, pname);
                                validSyms++;
                            }
                            else
                            {
                                ShowMsg("%04X:%08X - Change name to '%s' failed\n",
                                        seg, la, pname);
                                invalidSyms++;
                            }
                        }
                    }
                    else if (g_options.bReplace || !has_cmt(f))
                    {
                        // Apply symbols for comment
                        if (set_cmt(la, pname, false))
                        {
                            ShowMsg("%04X:%08X - Change comment to '%s' successed\n",
                                    seg, la, pname);
                            validSyms++;
                        }
                        else
                        {
                            ShowMsg("%04X:%08X - Change comment to '%s' failed\n",
                                    seg, la, pname);
                            invalidSyms++;
                        }
                    }
                }
            }
        }
    }
    __finally
    {
        MapFileClose(pMapStart);
        hide_wait_box();
    }

    if (!foundHdr)
    {
        warning("File '%s' is not a valid Map file", fname);
    }
    else
    {
        // Save file name for next askfile_c dialog
        strncpy(mapFileName, fname, sizeof(mapFileName));

        // Show the result
        msg("Result of loading and parsing the Map file '%s'\n"
            "   Number of Symbols applied: %d\n"
            "   Number of Invalid Symbols: %d\n\n",
            fname, validSyms, invalidSyms);
    }
}

////////////////////////////////////////////////////////////////////////////////
/**
 * global static term
 * @brief Plugin terminate function
 * @return void
 * @author TQN
 * @date 09/11/2004
 */
////////////////////////////////////////////////////////////////////////////////
static void idaapi term(void)
{
    msg("LoadMap: Plugin terminate.\n");

    // Write the plugin's options to ini file
    _VERIFY(WritePrivateProfileStruct(g_szLoadMapSection, g_szOptionsKey, &g_options,
                                      sizeof(g_options), g_szIniPath));
}

//--------------------------------------------------------------------------
//  Plugin information.
//--------------------------------------------------------------------------
static char wanted_name[]   = "LoadMap - Load Symbols From Map File";
static char wanted_hotkey[] = "Ctrl-M";
static char comment[]       = "LoadMap loads symbols from a VC/Borland/Dede map file.";
static char help[]          = "LoadMap, VC/Borland/Dede map file import plugin."
                              "This module reads an accompanying map file,\n"
                              "and loads symbols into IDA database.";

//--------------------------------------------------------------------------
//  Plugin description block.
//--------------------------------------------------------------------------
extern "C" {
    plugin_t PLUGIN = {
        IDP_INTERFACE_VERSION,
        0,                      //  Plugin flags (not used).
        init,                   //  Initialize.
        term,                   //  Terminate (not used).
        run,                    //  Main function.
        comment,
        help,
        wanted_name,
        wanted_hotkey
    };
}

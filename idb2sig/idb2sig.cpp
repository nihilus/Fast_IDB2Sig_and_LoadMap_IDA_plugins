/*************************************************************************
    IDB2SIG plugin
    Rewrite and add some abilyties by TQN (truong_quoc_ngan@yahoo.com)
    Reuse some code from IDB2PAT of J.C. Roberts <mercury@abac.com>

    Original written by Quine (quine@blacksun.res.cmu.edu) and Darko
    Visit Quine's IDA Page at http://surf.to/quine_ida

    Contribute to ExeTools and Woodmann forum and community
**************************************************************************
Revision History :
Version   Author    Date       Description
  V1.0    Quine    ??????????  creation.
  V1.1    Darko    04.10.2002  modification for IDA Pro v4.3 and SDK 4.3.
  V1.2    Darko    05.10.2002  pat file opened in appending mode.
  V1.3    Darko    21.12.2002  bug fix for reference bad address.
  V1.4    TQN      30.08.2004  bug fix for reference bad address.
                               some code optimize.
                               add options dialog.
                               add save and restore options to and from INI file.
                               Compile for IDA Pro v4.5.
  V1.5	  Swine	   06.10.2011  Fixed behavior for 64-bit disassemblies
							   Compile for IDA Pro v6.1

*************************************************************************/

#include "stdafx.h"
#include "idb2sig.h"

using namespace std;

static HINSTANCE g_hinstPlugin = NULL;
static char g_szIniPath[MAX_PATH] = { 0 };
static char g_szPatFile[MAX_PATH] = { 0 };

/* Global variable for options */
static PLUGIN_OPTIONS g_options;

/* Ini Section and Key names */
static char g_szIDB2SIGSection[] = "IDB2SIG";
static char g_szOptionsKey[] = "Options";

/* CRC_CCITT table and poly */
#define POLY 0x8408
static uint CRC_CCITT_TABLE[256];

typedef map<ea_t, ea_t, less<ea_t> > ref_map;

/**********************************************************************
* Function: PageFaultExceptionFilter
* Description:
*   SEH exception filter to commit pages from the reserved region.
*   Whenever a page fault exception occurs, this function is executed.
*   If it can allocate another page, the execution continues at the
*   point where the exception occurred. Otherwise, the exception handler
*   is executed.
* Returns: Exception code
**********************************************************************/
static int PageFaultExceptionFilter(IN DWORD dwCode, IN OUT LPSTR *lppNextPage)
{
    LPVOID lpvResult = NULL;

    _ASSERTE(lppNextPage != NULL);

    // If the exception is not a page fault, exit.
    if (EXCEPTION_ACCESS_VIOLATION != dwCode)
    {
        (void) msg("IDB2SIG: Exception occurred. Exception code = 0x%08X.\n", dwCode);
        return EXCEPTION_EXECUTE_HANDLER;
    }

    // Otherwise, commit another 1MB of virtual memory.
    lpvResult = VirtualAlloc(*lppNextPage,       // next page address to commit
                             ONE_MB,
                             MEM_COMMIT,        // allocate committed pages
                             PAGE_READWRITE);   // read/write access
    if (NULL == lpvResult)
    {
        (void) msg("IDB2SIG: Call VirtualAlloc to commit memory failed."
                   " Run out of reversing virtual memory."
                   "\tPlease increase the size of reversing virtual memory.\n");
        return EXCEPTION_EXECUTE_HANDLER;
    }

    // Advance pNextPage to the next reserve page.
    *lppNextPage += ONE_MB;

    // Continue execution where the page fault occurred.
    return EXCEPTION_CONTINUE_EXECUTION;
}

/**********************************************************************
* Function:    GetLine
* Description:
* Reads a line from file f, up to the size of the buffer.  The line in the
* buffer will NOT include line termination, although any of (CR, LF, CRLF)
* is accepted on input.  The return value is < 0 on error, 0 if the line
* was terminated abnormally (EOF, error, or out of buffer space), and
* length (of the line) if the line was terminated normally.
*
* Passing in a buffer less than 2 characters long is not a terribly bright
* idea.
* Parameters:  char *szBuf
*              uint maxLen
*              FILE *fp
* Returns:     int - buffer length or error code if < 0
**********************************************************************/
static int GetLine(char *szBuf, uint maxLen, FILE *fp)
{
    _ASSERTE(fp != NULL);
    _ASSERTE(szBuf != NULL);
    _ASSERTE(maxLen > 0);
    if ((NULL == szBuf) || (NULL == fp) || (0 == maxLen))
    {
        (void) msg("IDB2SIG - %s(%d) : Incorrect function input arguments.\n",
                   __FILE__, __LINE__);
        return -1;
    }

    memset(szBuf, 0, maxLen);
    char *pStr = szBuf;
    int state = 0;
    for (;;)
    {
        int ch = qfgetc(fp);

        if ('\n' == ch)
        {
            *pStr = 0;
            return (int) strlen(szBuf);   /* Line terminated with \n or \r\n */
        }

        if (state != 0)
        {
            *pStr = 0;
            (void) qfseek(fp, -1L, SEEK_CUR);
            return (int) strlen(szBuf);   /* Line terminated with \r */
        }

        if (feof(fp))
        {
            *pStr = 0;
            clearerr(fp);
            return (pStr == szBuf) ? -1 : -2;   /* Error */
        }

        if (ferror(fp))
        {
            *pStr = 0;
            clearerr(fp);
            return -3;      /* Error */
        }

        if ('\r' == ch)
        {
            state = 1;
        }
        else
        {
            if (--maxLen > 0)
            {
                *pStr++ = (char) ch;
            }
            else
            {
                *pStr = 0;
                (void) qfseek(fp, -1L, SEEK_CUR);
                return -4;      /* Out of buffer space */
            }
        }
    }
} /* end of getLine */

/**********************************************************************
* Function:    SkipBackward
* Description: scrolls a number of lines backward from current position in file
*              IT IS A NASTY ONE!!
* Parameters:  FILE *fp
*              int numOfRows
* Returns:     int
**********************************************************************/
static int SkipBackward(FILE *fp, int numOfRows)
{
    int c = 0;

    _ASSERTE(fp != NULL);
    _ASSERTE(numOfRows > 0);
    if ((NULL == fp) || (numOfRows <= 0))
    {
        (void) msg("IDB2SIG - %s(%d) : Incorrect function input arguments.\n",
                   __FILE__, __LINE__);
        return 1;
    }

    while (numOfRows > 0)
    {
        if (qftell(fp) >= 2)
        {
            if (qfseek(fp, -2L, SEEK_CUR))
            {
                clearerr(fp);
                (void) qfseek(fp, 0L, SEEK_SET);
                return 1;
            }
        }
        else
        {
            (void) qfseek(fp, 0L, SEEK_SET);
        }

        c = qfgetc(fp);

        if (feof(fp))
        {
            clearerr(fp);
            return 1;
        }

        if ('\n' == c)
        {
            numOfRows--;
        }

        if (1 == qftell(fp))
        {
            (void) qfseek(fp, 0L, SEEK_SET);
            return 0;
        }
    }

    return 0;
} /* end of SkipBackward */

/* Init the table lookup for CRC_CCITT 16 calculation */
static void InitCRCTable(void)
{
    for (uint i = 0; i < 256; i++)
    {
        uint crc = i;
        for (int j = 0; j < 8; j++)
        {
            if (crc & 1)
                crc = (crc >> 1) ^ POLY;
            else
                crc >>= 1;
        }
        CRC_CCITT_TABLE[i] = crc;
    }
}

/**********************************************************************
* Function:     crc16
* Description:
*   crc16 is ripped straight out the c file that comes with the
*   FLAIR package
*                                        16   12   5
*   this is the CCITT CRC 16 polynomial X  + X  + X  + 1.
*   This works out to be 0x1021, but the way the algorithm works
*   lets us use 0x8408 (the reverse of the bit pattern).  The high
*   bit is always assumed to be set, thus we only use 16 bits to
*   represent the 17 bit value.
* Parameters: uchar *pdata - pointer to data
*             uint16 len - data length
* Returns:    CRC
* Optimize by TQN, run faster about 12 times
**********************************************************************/
static uint16 crc16(const uchar *pdata, uint16 len)
{
    _ASSERTE(pdata != NULL);
    if (NULL == pdata)
    {
        (void) msg("IDB2SIG - %s(%d) : Incorrect function input arguments.\n",
                   __FILE__, __LINE__);
        return 0;
    }

    if (0 == len)
    {
        return 0;
    }

    uint data;
    uint crc = 0xFFFF;
    do
    {
        data = *pdata++;
        crc = (crc >> 8) ^ CRC_CCITT_TABLE[(crc ^ data) & 0xFF];
    } while (--len);

    crc = ~crc;
    data = crc;
    crc = (crc << 8) | ((data >> 8) & 0xFF);

    return (uint16) crc;
}

/**********************************************************************
* Function:     Num2HexStr
* Description:  Convert a number to a hex string
* Parameters:   pBuf: Pointer to buffer to store the result hex string.
*               The caller must ensure buffer have enough space to store
*               len of hex characters and a NULL character.
*               len: number of hex character required. The buffer will be
*               add 0 to the left to ensure have have len hex characters
*               num: number will be converted
* Returns:      The pointer to the next last written character to pBuf
**********************************************************************/
static inline char* Num2HexStr(char *pBuf, uint len, uint num)
{
    static const char HEXSTR[] = "0123456789ABCDEF";

    _ASSERTE(pBuf != NULL);
    if (NULL == pBuf)
    {
        (void) msg("IDB2SIG - %s(%d) : Invalid function input arguments.\n",
                   __FILE__, __LINE__);
        return pBuf;
    }

    char *p = pBuf + len;
    *p-- = '\0';
    while (p >= pBuf)
    {
        int digit = num & 0x0F;
        num >>= 4;
        *p-- = HEXSTR[digit];
    }

    return (pBuf + len);
}

/**********************************************************************
* Function:     find_ref_loc
* Description:
*   this function finds the location of a reference within an instruction
*   or a data item
*   eg:  00401000 E8 FB 0F 00 00   call sub_402000
*   find_ref_loc(0x401000, 0x402000) would return 0x401001
*   it works for both segment relative and self-relative offsets
*   all references are assumed to be 4 bytes long
* Parameters:   ea_t item
*               ea_t _ref
* Returns:      ea_t
				*ref_len : length of reference in bytes
**********************************************************************/
static ea_t find_ref_loc(ea_t item, ea_t _ref, uint *ref_len)
{
ea_t ref_orig = _ref;
    _ASSERTE(item != BADADDR);
    _ASSERTE(_ref != BADADDR);
    if ((BADADDR == item) || (BADADDR == _ref))
    {
        (void) msg("IDB2SIG - %s(%d) : Incorrect function input arguments.\n",
                   __FILE__, __LINE__);
        return BADADDR;
    }

/*  
// Swine 06/10/2011: removed as more sophisticated analysis is required to manage offset displacement in a deterministic manner;
// Swine 06/10/2011:	cheap and effective solution is just to check for any of displaced or absolute offset

	if (isCode(getFlags(item)))
    {
        (void) ua_ana0(item);
        if (cmd.Operands[0].type == o_near)
        {
            // we have got a self-relative reference
            _ref = _ref - get_item_end(item);
        }
    }
*/

ea_t item_end = get_item_end(item);

#ifdef __EA64__
    for (ea_t i = item; i <= get_item_end(item) - 8; i++)
    {
	uint64 v;
		v = get_qword(i);
        if (v == _ref || v == _ref - item_end)
        {
			*ref_len = 8;
            return i;
        }
    }
#endif


    for (ea_t i = item; i <= get_item_end(item) - 4; i++)
    {
	uint32 v;
		v = get_long(i);
        if (v == (uint32)_ref || (int32)(_ref - item_end) == (int64)(_ref - item_end) &&  v == (uint32)(_ref - item_end) )
        {
			*ref_len = 4;
            return i;
        }
    }


	msg("WARNING: Could not find ref loc (ea=%a, ref_orig=%a, ref=%a)\n", item, ref_orig, _ref);
    return BADADDR;
}

/**********************************************************************
* Function:     set_v_bytes
* Description:  marks off a string of bytes as variable
* Parameters:   bool_vec& bv
*               int pos
*               int len
* Returns:      none
**********************************************************************/
static inline void set_v_bytes(vector<bool> &bv, uint pos, uint len)
{
    _ASSERTE(pos + len <= bv.size());
    if (pos + len > bv.size())
    {
        (void) msg("IDB2SIG - %s(%d) : Incorrect function input arguments.\n",
                   __FILE__, __LINE__);
        return;
    }
    else
    {
        for (uint i = 0; i < len; i++)
        {
            bv[pos + i] = true;
        }
    }
}

/**********************************************************************
* Function:     make_func_sig
* Description:
*       this is what does the real work
*       given a starting address, a length, and a FILE pointer, it
*       writes a pattern line to the file
* Parameters:   ea_t start_ea
*               ulong len
*               FILE* f
* Returns:      none
**********************************************************************/
static size_t make_func_sig(ea_t start_ea, ulong len, char *pSigBuf)
{
    ea_t ea, ref, ref_loc;
	uint ref_len;

    uint first_string = 0, alen = 0;
    uint i = 0;
    uchar crc_data[256] = { 0 };
    uint16 crc = 0;
    flags_t flags = 0;
    char szName[MAXNAMELEN + 1] = { 0 };
    const char *pName = szName;
    vector<bool> v_bytes(len);
    vector<ea_t> v_publics;
    ref_map refs;

    _ASSERTE(start_ea != BADADDR);
    if (BADADDR == start_ea)
    {
        (void) msg("IDB2SIG - %s(%d) : Incorrect function input arguments.\n",
                   __FILE__, __LINE__);
        return 0;
    }

    if (len < g_options.ulMinFuncLen)
    {
	char buf[512];
		get_segm_name(start_ea, buf, sizeof buf);
        (void) msg("%s:%08X - Function length is %d and less than %d\n",
                   buf, start_ea, len, g_options.ulMinFuncLen);
        return 0;
    }

    ea = start_ea;
    while ((ea != BADADDR) && (ea - start_ea < len))
    {
        flags = getFlags(ea);
        if (has_name(flags) || ((ALL_FUNCTIONS == g_options.funcMode) && has_any_name(flags)))
        {
            v_publics.push_back(ea);
        }

        ref = get_first_dref_from(ea);
        if (BADADDR != ref)
        {
            // a data location is referenced
            ref_loc = find_ref_loc(ea, ref, &ref_len);
            if (BADADDR != ref_loc)
            {
                set_v_bytes(v_bytes, (uint)(ref_loc - start_ea), ref_len);
                refs[ref_loc] = ref;
            }

            // check if there is a second data location ref'd
            ref = get_next_dref_from(ea, ref);
            if (BADADDR != ref)
            {
                ref_loc = find_ref_loc(ea, ref, &ref_len);
                if (BADADDR != ref_loc)
                {
                    set_v_bytes(v_bytes, (uint)(ref_loc - start_ea), ref_len);
                    refs[ref_loc] = ref;
                }
            }
        }
        else
        {
            // do we have a code ref?
            ref = get_first_fcref_from(ea);
            if (BADADDR != ref)
            {
                // if so, make sure it is outside of function
                if ((ref < start_ea) || (ref >= start_ea + len))
                {
                    ref_loc = find_ref_loc(ea, ref, &ref_len);
                    if (BADADDR != ref_loc)
                    {
                        set_v_bytes(v_bytes, (uint)(ref_loc - start_ea), ref_len);
                        refs[ref_loc] = ref;
                    }
                }
            }
        }

        ea = next_not_tail(ea);
    }

    char *pc = pSigBuf;     // The increment pointer

    // write out the first string of bytes, making sure not to go past
    // the end of the function
    first_string = (len < 32 ? len : 32);
    for (i = 0; i < first_string; i++)
    {
        if (v_bytes[i])
        {
            *pc++ = DOT;
            *pc++ = DOT;
        }
        else
        {
            pc = Num2HexStr(pc, 2, get_byte(start_ea + i));
        }
    }

    // fill in anything less than 32
    for (i = 0; i < 32 - first_string; i++)
    {
        *pc++ = DOT;
        *pc++ = DOT;
    }

    // put together the crc data
    uint pos = 32;
    while ((pos < len) && !v_bytes[pos] && (pos < 255 + 32))
    {
        crc_data[pos - 32] = get_byte(start_ea + pos);
        pos++;
    }

    // alen is length of the crc data
    alen = pos - 32;
    crc = crc16(crc_data, (uint16) alen);

    // Format alen, crc and len to " %02X %04X %04X" format
    *pc++ = SPACE;
    pc = Num2HexStr(pc, 2, alen);
    *pc++ = SPACE;
    pc = Num2HexStr(pc, 4, crc);
    *pc++ = SPACE;
    pc = Num2HexStr(pc, 4, len);

    // write the publics
    for (vector<ea_t>::const_iterator p = v_publics.begin(); p != v_publics.end(); p++)
    {
        pName = get_true_name(BADADDR , *p, szName, sizeof(szName));

        // Make sure we have a name when all functions mode specified or
        // it is a user-specified name (valid name & !dummy prefix)
        if ((NULL != pName) && (is_uname(pName) || (ALL_FUNCTIONS == g_options.funcMode)))
        {
            // Format pSigBuf with " :%04X " or " :-%04X " format
            // Check for negative offset and adjust output
            *pc++ = SPACE;
            *pc++ = ':';
            if (*p >= start_ea)
            {
                pc = Num2HexStr(pc, 4, (uint)(*p - start_ea));
                *pc++ = SPACE;
            }
            else
            {
                *pc++ = '-';
                pc = Num2HexStr(pc, 4, (long)(start_ea - *p));
                *pc ++ = SPACE;
            }

            while (*pName != '\0')
            {
                *pc++= *pName++;
            }
        }
    }

    // write the references
    for (ref_map::const_iterator r = refs.begin(); r != refs.end(); r++)
    {
        pName = get_true_name(BADADDR, (*r).second, szName, sizeof(szName));
        flags = getFlags((*r).second);

        // Make sure we have a name when all functions mode specified or
        // it is a user-specified name
        if ((NULL != pName) && (has_user_name(flags) || (ALL_FUNCTIONS == g_options.funcMode)))
        {
            // Format pSigBuf with " ^%04X " or " ^-%04X " format
            // Check for negative offset and adjust output
            *pc++ = SPACE;
            *pc++ = '^';
            if ((*r).first >= start_ea)
            {
                pc = Num2HexStr(pc, 4, (uint)((*r).first - start_ea));
                *pc++ = SPACE;
            }
            else
            {
                *pc++ = '-';
                pc = Num2HexStr(pc, 4, (uint)(start_ea - (*r).first));
                *pc++ = SPACE;
            }

            while (*pName != '\0')
            {
                *pc++= *pName++;
            }
        }
    }

    // and finally write out the last string with the rest of the function
    *pc++ = SPACE;
    for (i = pos; i < len; i++)
    {
        if (v_bytes[i])
        {
            *pc++ = DOT;
            *pc++ = DOT;
        }
        else
        {
            pc = Num2HexStr(pc, 2, get_byte(start_ea + i));
        }
    }

    *pc++ = '\r';
    *pc++ = '\n';

    return (size_t) (pc - pSigBuf);
}

/**********************************************************************
* Function:     get_pat_file
* Description:  open and prepare output file for write
* Parameters:   none
* Returns:      FILE*
**********************************************************************/
static FILE* get_pat_file(void)
{
    int i = 0;
    long pos = 0;
    FILE *fp = NULL;
    char szLine[50] = { 0 };
    char *filename = NULL;

    if ('\0' == g_szPatFile[0])
    {
        /* First run */
	char buf[512];
		get_input_file_path(buf, sizeof buf);
        strncpy(g_szPatFile, buf, countof(g_szPatFile));
        _VERIFY(PathRenameExtension(g_szPatFile, ".pat"));
    }

AskFile:
    filename = askfile_c(1, g_szPatFile, "Enter the name of the pattern file:");
    if (NULL == filename)
    {
        (void) msg("IDB2SIG: User chose cancel.\n");
        return NULL;
    }

    if (g_options.bPatAppend)
    {
        /* Open existing PAT file for read and write */
        fp = qfopen(filename, "r+b");
    }
    else
    {
        /* In overwrite mode */
        if (g_options.bConfirm && PathFileExists(filename))
        {
            /* Confirm is true, confirm overwrite the existing file */
            int ret = askyn_c(-1, "Do you want to overwrite the existing file %s", filename);
            if (-1 == ret)
            {
                /* User chose cancel */
                return NULL;
            }
            else if (0 == ret)
            {
                /* User chose no button, select another file */
                goto AskFile;
            }
        }
    }

    if (NULL == fp)
    {
        /*
         * In appending mode, if the file did not exist, create it
         * In overwrite mode, creating a new or overwrite an existing file
         */
        fp = qfopen(filename, "w+b");
    }

    if (NULL == fp)
    {
        warning("Could not create or open file %s.\n", filename);
        return NULL;
    }

    /* Save file name for next askfile_c dialog */
    strncpy(g_szPatFile, filename, countof(g_szPatFile));
    g_szPatFile[countof(g_szPatFile) - 1] = '\0';

    /*
     * This section tests if pat file exists and overwrite '---' at the end
     * in the file append mode
     */
    if (g_options.bPatAppend)
    {
        (void) qfseek(fp, 0L, SEEK_END);        /* go to end_of_file */
        pos = qftell(fp);
        if (pos != 0)
        {
            /* pat file is not empty */
            do
            {
                (void) SkipBackward(fp, 1);     /* one line back */
                pos = qftell(fp);
                i = GetLine(szLine, sizeof(szLine), fp);
                if (i == 0)                     /* skip empty lines at the end of file */
                {
                    (void) SkipBackward(fp, 1); /* one more line back */
                }
            } while (i == 0);                   /* skip empty lines at the end of file */

            if (i < 0)
            {
                warning("Something is wrong with %s or '---' is missing!\n", filename);
                (void) qfclose(fp);
                return NULL;                    /* abandon ship */
            }

            if (i > 0)
            {
                if (strcmp(szLine, "---"))
                {
                    warning("%s is not a valid PAT file!\n", filename);
                    (void) qfclose(fp);
                    return NULL;                /* abandon ship */
                }
            }

            (void) qfseek(fp, pos, SEEK_SET);   /* overwrite '---' */
        }
    }

    return fp;
}

/* The DLL entry point of plugin */
BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID)
{
    if (DLL_PROCESS_ATTACH == fdwReason)
    {
        _VERIFY(DisableThreadLibraryCalls(g_hinstPlugin = hinstDLL));
    }

    return TRUE;
}

/**********************************************************************
* Function:     ShowOptionsDlg
* Description:  Show options dialog for getting user desired options
* Parameters:   none
* Returns:      none
**********************************************************************/
static void ShowOptionsDlg(void)
{
    // Build the format string constant used to create the dialog
    const char format[] =
        "STARTITEM 0\n"                                                 // TabStop
        "IDB2SIG Options\n\n"                                           // Title
        "Choose the method for selecting functions:\n"                  // MsgText

        //  Radio Button 0x0000 - NON_AUTO_FUNCTIONS
        "<#Create patterns for all functions with user created names.\n" // hint0
        "This excludes all library functions and auto-generated names.#" // hint0
        "Non-Auto Named Functions:R>\n"                                  // text0

        //  Radio Button 0x0001 - LIBRARY_FUNCTIONS
        "<#Create patterns for functions maked as libraries.\n"         // hint1
        "This excludes all auto-generated names.#"                      // hint1
        "Library Functions Only:R>\n"                                   // text1

        //  Radio Button 0x0002 - PUBLIC_FUNCTIONS
        "<#Create patterns for functions marked as public.\n"           // hint2
        "This excludes all auto-generated names.#"                      // hint2
        "Public Functions Only:R>\n"                                    // text2

        //  Radio Button 0x0003 - ENTRY_POINT_FUNCTIONS
        "<#Create patterns for functions marked as entry point.\n"      // hint3
        "This excludes all auto-generated names.#"                      // hint3
        "Entry Point Functions Only:R>\n"                               // text3

        //  Radio Button 0x0004 - ALL_FUNCTIONS
        "<#Create Patterns For Everything.\n"
        "CAUTION -This will make a real mess of names in any\n"         // hint4
        "disassembly where the resulting signature is applied.#"        // hint4
        "All Functions:R>\n"                                            // text4

        //  Radio Button 0x0005 - USER_SELECT_FUNCTION
        "<#Select a function from a dialog with a list of functions.#"  // hint5
        "User Selected Function:R>>\n\n"                                // text5

        //  Checkbox Button - Append PAT file
        "<#Append or overwrite the existing PAT file.#"                 // hint6
        "Append To Existing PAT file:C>\n"                              // text6

        //  Checkbox Button - Confirm overwrite
        "<#Display a message box to confirm overwriting an existing file#"  // hint7
        "Confirm Overwrite:C>>\n\n"                                     // text7

        //  Editbox - Minimum function length
        "<#The minimum function length (in bytes).\n"                   // hint8
        "The signature will not be created for any\n"
        "functions less than this specified length.\n"
        "Default and minimum is 6.#"
        "Minimum Function Length  :D:8:::>\n\n"                         // text8

        //  Editbox - The size of reversing virtual memory size
        "<#The size (in MB) of virtual memory will be reversed.\n"      // hint9
        "To improve speed, this plugin will reverse with this size and\n"
        "dynamic commit 1 MB of virtual memory to create all signature\n"
        "lines in memory before writing to disk. Default and minimum is 10 MB.\n"
        "If an exception occur, please increase this size. Otherwise,\n"
        "if and an out of memory occur, please decrease this size.#"
        "Size Of Virtual Memory Reversing (in MB)  :D:8:::>\n\n";       // text9

    // Create the option dialog.
    short mode = (short) g_options.funcMode;
    short chkMask = 0;
    if (g_options.bPatAppend)
    {
        chkMask |= 1;
    }
    if (g_options.bConfirm)
    {
        chkMask |= 2;
    }
    long len = (long) g_options.ulMinFuncLen;
    long size = (long) g_options.ulReverseSize;
    if (AskUsingForm_c(format, &mode, &chkMask, &len, &size))
    {
        g_options.funcMode = (FUNCTION_MODE) mode;
        g_options.bPatAppend = ((chkMask & 1) != 0);
        g_options.bConfirm = ((chkMask & 2) != 0);

        if (len < DEF_MIN_FUNC_LENGTH)
        {
            (void) msg("Value inputted for minimum function length is invalid."
                       " Get default value is %d.\n", DEF_MIN_FUNC_LENGTH);
        }
        g_options.ulMinFuncLen = (ulong) max(len, DEF_MIN_FUNC_LENGTH);

        if (size < DEF_REVERSE_SIZE)
        {
            (void) msg("Value inputted for size of virtual memory reversing is invalid."
                       " Get default value is %d MB.\n", DEF_REVERSE_SIZE);
        }
        g_options.ulReverseSize = (ulong) max(size, DEF_REVERSE_SIZE);
    }
}

/**********************************************************************
* Function:     init
* Description:  Plugin init
* Parameters:   none
* Returns:      PLUGIN_OK
**********************************************************************/
static int idaapi init(void)
{
    (void) msg("IDB2SIG: Plugin init.\n");

    InitCRCTable();

    /* Get the full path of plugin */
    _VERIFY(GetModuleFileName(g_hinstPlugin, g_szIniPath, countof(g_szIniPath)));
    g_szIniPath[countof(g_szIniPath) - 1] = '\0';

    /* Change the extension of plugin to '.ini'. */
    _VERIFY(PathRenameExtension(g_szIniPath, ".ini"));

    /* Get options saved in ini file */
    _VERIFY(GetPrivateProfileStruct(g_szIDB2SIGSection, g_szOptionsKey, &g_options,
                                     sizeof(g_options), g_szIniPath));

    /* Check and validate all members in global options */
    g_options.funcMode = min(FUNCTION_MODE_MAX, max(FUNCTION_MODE_MIN, g_options.funcMode));
    g_options.ulMinFuncLen = max(DEF_MIN_FUNC_LENGTH, g_options.ulMinFuncLen);
    g_options.ulReverseSize = max(DEF_REVERSE_SIZE, g_options.ulReverseSize);

    return PLUGIN_KEEP;
}

/**********************************************************************
* Function:     term
* Description:  Plugin terminate
* Parameters:   none
* Returns:      none
**********************************************************************/
static void idaapi term(void)
{
    (void) msg("IDB2SIG: Plugin terminate.\n");

    /* Write options to ini file */
    _VERIFY(WritePrivateProfileStruct(g_szIDB2SIGSection, g_szOptionsKey, &g_options,
                                      sizeof(g_options), g_szIniPath));
}

/**********************************************************************
* Function:     run
* Description:  entry function of the plugin
* Parameters:   int arg
* Returns:      none
**********************************************************************/
static void idaapi run(int /*arg*/)
{
    func_t* pFunc = NULL;
    LPSTR pSigBuf = NULL;
    LPSTR pNextPage = NULL;

    // If user press shift key, show options dialog
    if (GetAsyncKeyState(VK_SHIFT) & 0x8000)
    {
        ShowOptionsDlg();
    }

    int numOfFuncs = get_func_qty();
    if (numOfFuncs <= 0)
    {
        (void) msg("IDB2SIG: Not found any functions\n");
        return;
    }

    // Preprocess for user select function mode
    if (USER_SELECT_FUNCTION == g_options.funcMode)
    {
        pFunc = choose_func("Choose Function:", ea_t(-1));
        if (NULL == pFunc)
        {
            (void) msg("IDB2SIG: User not select any function!\n");
            return;
        }

        // Move the cursor to selected function
        jumpto(pFunc->startEA);

        if (!has_any_name(getFlags(pFunc->startEA)))
        {
            (void) msg("IDB2SIG: The current function does not have any name.\n");
            return;
        }
    }

    // Reserve a large block of virtual memory.
    pSigBuf = pNextPage = (LPSTR) VirtualAlloc(NULL,
                                               g_options.ulReverseSize * ONE_MB,
                                               MEM_RESERVE,
                                               PAGE_NOACCESS);
    if (NULL == pSigBuf)
    {
        (void) msg("IDB2SIG: Call VirtualAlloc to reserve %d MB of virtual memory failed.\n"
                   "\tPlease decrease the size of reversing virtual memory.\n",
                   g_options.ulReverseSize);
        return;
    }

    FILE *fp = get_pat_file();
    if (NULL == fp)
    {
        // Release the block of memory pages
        _VERIFY(VirtualFree(pSigBuf, 0, MEM_RELEASE));
        return;
    }

    show_wait_box("Creating FLAIR PAT file %s.", g_szPatFile);

    __try
    {
        __try
        {
            int i = 0;
            size_t len = 0;
            switch (g_options.funcMode)
            {
                case NON_AUTO_FUNCTIONS:    // write all non auto-generated name functions
                    for (i = 0; i < numOfFuncs; i++)
                    {
                        pFunc = getn_func(i);
                        if ((NULL != pFunc) && has_name(getFlags(pFunc->startEA)) &&
                            !(pFunc->flags & FUNC_LIB))
                        {
                            len += make_func_sig(pFunc->startEA,
                                                (ulong)(pFunc->endEA - pFunc->startEA),
                                                &pSigBuf[len]);
                        }
                    }
                    break;

                case LIBRARY_FUNCTIONS: // write all library functions
                    for (i = 0; i < numOfFuncs; i++)
                    {
                        pFunc = getn_func(i);
                        if ((NULL != pFunc) && (pFunc->flags & FUNC_LIB))
                        {
                            len += make_func_sig(pFunc->startEA,
                                                (ulong)(pFunc->endEA - pFunc->startEA),
                                                &pSigBuf[len]);
                        }
                    }
                    break;

                case PUBLIC_FUNCTIONS:  // write all public function
                    for (i = 0; i < numOfFuncs; i++)
                    {
                        pFunc = getn_func(i);
                        if ((NULL != pFunc) && is_public_name(pFunc->startEA))
                        {
                            len += make_func_sig(pFunc->startEA,
                                                (ulong)(pFunc->endEA - pFunc->startEA),
                                                &pSigBuf[len]);
                        }
                    }
                    break;

                case ENTRY_POINT_FUNCTIONS:   // write all entry point functions
                    for (i = 0; i < numOfFuncs; i++)
                    {
                        pFunc = get_func(get_entry(get_entry_ordinal((ulong) i)));
                        if (NULL != pFunc)
                        {
                            len += make_func_sig(pFunc->startEA,
                                                (ulong)(pFunc->endEA - pFunc->startEA),
                                                &pSigBuf[len]);
                        }
                    }
                    break;

                case ALL_FUNCTIONS:
                    for (i = 0; i < numOfFuncs; i++)
                    {
                        pFunc = getn_func(i);
                        if (NULL != pFunc)
                        {
                            len += make_func_sig(pFunc->startEA,
                                                (ulong)(pFunc->endEA - pFunc->startEA),
                                                &pSigBuf[len]);
                        }
                    }
                    break;

                case USER_SELECT_FUNCTION:
                    // Write the current function or user select function
                    _ASSERTE(pFunc != NULL);
                    if (NULL != pFunc)
                    {
                        len = make_func_sig(pFunc->startEA,
                                            (ulong)(pFunc->endEA - pFunc->startEA),
                                            pSigBuf);
                    }
                    break;

                default:
                    __assume(0);
                    break;
            }

            if (len > 0)
            {
                // Append the terminate signature of pat file
                strcpy(&pSigBuf[len], "---\r\n");
                len += 5;

                if (len != (size_t) qfwrite(fp, pSigBuf, len))
                {
                    (void) msg("IDB2SIG: Write all signature lines to PAT file %s failed.n",
                            g_szPatFile);
                }
                else
                {
                    (void) msg("IDB2SIG: Creating PAT file %s successed.\n",
                            g_szPatFile);
                }
            }
            else
            {
                (void) msg("Did not create any signature lines.\n");
            }
        }
        __except (PageFaultExceptionFilter(GetExceptionCode(), &pNextPage))
        {
            (void) msg("Creating PAT file %s failed.\n", g_szPatFile);
        }
    }
    __finally
    {
        hide_wait_box();

        (void) qfclose(fp);

        // Release the block of memory pages
        _VERIFY(VirtualFree(pSigBuf, 0, MEM_RELEASE));
    }
}

//--------------------------------------------------------------------------
char help[] = "This plugin converts a function or set of functions to a FLAIR PAT file";
char comment[] = "Convert a function or functions to a FLAIR PAT file";
char wanted_name[] = "IDB2SIG - Create FLAIR PAT file";
char wanted_hotkey[] = "Ctrl-F7";

//--------------------------------------------------------------------------
//
//      PLUGIN DESCRIPTION BLOCK
//
//--------------------------------------------------------------------------

extern "C" {
    plugin_t PLUGIN = {
    IDP_INTERFACE_VERSION,
    0,                      // plugin flags
    init,                   // initialize
    term,                   // terminate. this pointer may be NULL.
    run,                    // invoke plugin
    comment,                // long comment about the plugin
                            // it could appear in the status line
                            // or as a hint
    help,                   // multiline help about the plugin
    wanted_name,            // the preferred short name of the plugin
    wanted_hotkey           // the preferred hotkey to run the plugin
};
}

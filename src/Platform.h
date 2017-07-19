#pragma once

/* \todo add stackoverflow link to source */

#ifdef WIN32

#include <stdint.h>
#include <stdlib.h>
#include <Windows.h>
#include <sddl.h>

#include <iostream>
#include <iomanip>
#include <memory>

#pragma comment(lib, "Advapi32.lib")

#define _CRT_INTERNAL_NONSTDC_NAMES 1
#include <sys/stat.h>

#if defined __WIN32__ || defined _WIN32 || defined _Windows
#  if !defined S_ISDIR
#    define S_ISDIR(m) (((m) & _S_IFDIR) == _S_IFDIR)
#    define S_ISREG(m) (((m) & _S_IFREG) == _S_IFREG)
#    define S_ISCHR(m) (((m) & _S_IFCHR) == _S_IFCHR)
#    define S_ISFIFO(m) (((m) & _S_IFIFO) == _S_IFIFO)
#    define S_ISLNK(m) (false)
#    define S_ISBLK(m) (false)
#    define S_ISSOCK(m) (false)
#  endif
#endif

#define X_OK 00
#define R_OK 04

#include <io.h>
#include <direct.h>
#include <process.h>

#define strcasecmp  stricmp
#define lstat        ::_stat
#define stat        _stat64i32
#define chdir       _chdir
#define getpid      _getpid

using mode_t = unsigned int;
using nlink_t = unsigned int;


struct heap_delete
{
    typedef LPVOID pointer;
    void operator()(LPVOID p)
    {
        ::HeapFree(::GetProcessHeap(), 0, p);
    }
};
typedef std::unique_ptr<LPVOID, heap_delete> heap_unique_ptr;

struct handle_delete
{
    typedef HANDLE pointer;
    void operator()(HANDLE p)
    {
        ::CloseHandle(p);
    }
};
typedef std::unique_ptr<HANDLE, handle_delete> handle_unique_ptr;

typedef uint32_t uid_t;

static
BOOL GetUserSID(HANDLE token, PSID* sid)
{
    if (
        token == nullptr || token == INVALID_HANDLE_VALUE
        || sid == nullptr
        )
    {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }
    DWORD tokenInformationLength = 0;
    ::GetTokenInformation(
        token, TokenUser, nullptr, 0, &tokenInformationLength);
    if (GetLastError() != ERROR_INSUFFICIENT_BUFFER)
    {
        return FALSE;
    }
    heap_unique_ptr data(
        ::HeapAlloc(
            ::GetProcessHeap(), HEAP_ZERO_MEMORY,
            tokenInformationLength));
    if (data.get() == nullptr)
    {
        return FALSE;
    }
    BOOL getTokenInfo = ::GetTokenInformation(
        token, TokenUser, data.get(),
        tokenInformationLength, &tokenInformationLength);
    if (!getTokenInfo)
    {
        return FALSE;
    }
    PTOKEN_USER pTokenUser = (PTOKEN_USER)(data.get());
    DWORD sidLength = ::GetLengthSid(pTokenUser->User.Sid);
    heap_unique_ptr sidPtr(
        ::HeapAlloc(
            GetProcessHeap(), HEAP_ZERO_MEMORY, sidLength));
    PSID sidL = (PSID)(sidPtr.get());
    if (sidL == nullptr)
    {
        return FALSE;
    }
    BOOL copySid = ::CopySid(sidLength, sidL, pTokenUser->User.Sid);
    if (!copySid)
    {
        return FALSE;
    }
    if (!IsValidSid(sidL))
    {
        return FALSE;
    }
    *sid = sidL;
    sidPtr.release();
    return TRUE;
}
static
uid_t GetUID(HANDLE token)
{
    PSID sid = nullptr;
    BOOL getSID = GetUserSID(token, &sid);
    if (!getSID || !sid)
    {
        return -1;
    }
    heap_unique_ptr sidPtr((LPVOID)(sid));
    LPWSTR stringSid = nullptr;
    BOOL convertSid = ::ConvertSidToStringSidW(
        sid, &stringSid);
    if (!convertSid)
    {
        return -1;
    }
    uid_t ret = -1;
    LPCWSTR p = ::wcsrchr(stringSid, L'-');
    if (p && ::iswdigit(p[1]))
    {
        ++p;
        ret = ::_wtoi(p);
    }
    ::LocalFree(stringSid);
    return ret;
}
static
uid_t getuid()
{
    HANDLE process = ::GetCurrentProcess();
    handle_unique_ptr processPtr(process);
    HANDLE token = nullptr;
    BOOL openToken = ::OpenProcessToken(
        process, TOKEN_READ | TOKEN_QUERY_SOURCE, &token);
    if (!openToken)
    {
        return -1;
    }
    handle_unique_ptr tokenPtr(token);
    uid_t ret = GetUID(token);
    return ret;
}
static
uid_t geteuid()
{
    HANDLE process = ::GetCurrentProcess();
    HANDLE thread = ::GetCurrentThread();
    HANDLE token = nullptr;
    BOOL openToken = ::OpenThreadToken(
        thread, TOKEN_READ | TOKEN_QUERY_SOURCE, FALSE, &token);
    if (!openToken && ::GetLastError() == ERROR_NO_TOKEN)
    {
        openToken = ::OpenThreadToken(
            thread, TOKEN_READ | TOKEN_QUERY_SOURCE, TRUE, &token);
        if (!openToken && ::GetLastError() == ERROR_NO_TOKEN)
        {
            openToken = ::OpenProcessToken(
                process, TOKEN_READ | TOKEN_QUERY_SOURCE, &token);
        }
    }
    if (!openToken)
    {
        return -1;
    }
    handle_unique_ptr tokenPtr(token);
    uid_t ret = GetUID(token);
    return ret;
}

#endif // WIN32

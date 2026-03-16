#pragma once
#define _WINSOCK_DEPRECATED_NO_WARNINGS
#include <WinSock2.h>
#include <Windows.h>

VOID DisableHooks();
VOID removeHooks(HMODULE hmodule);

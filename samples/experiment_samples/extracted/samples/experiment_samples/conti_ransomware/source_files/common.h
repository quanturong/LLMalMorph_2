#pragma once
#define _WINSOCK_DEPRECATED_NO_WARNINGS
#define WIN32_LEAN_AND_MEAN

#include <WinSock2.h>
#include <Windows.h>
#include <string>

#include "obfuscation/MetaString.h"
#include "queue.h"
#include "memory.h"

#ifndef EXE_BUILD
#define EXE_BUILD
#endif
#define STATIC static

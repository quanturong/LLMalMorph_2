#pragma once
#include "../common.h"

enum EncryptModes {

	ALL_ENCRYPT = 10,
	LOCAL_ENCRYPT = 11,
	NETWORK_ENCRYPT = 12,
	BACKUPS_ENCRYPT = 13,
	PATH_ENCRYPT = 14

};

namespace global {

	VOID SetEncryptMode(INT EncryptMode);
	INT GetEncryptMode();
	VOID SetEncryptSize(INT Size);
	INT GetEncryptSize();
	VOID SetProcKiller(BOOL IsEnabled);
	BOOL GetProcKiller();

}

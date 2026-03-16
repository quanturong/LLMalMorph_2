#include "global_parameters.h"

// ORIGINAL

STATIC INT g_EncryptMode = ALL_ENCRYPT;
STATIC INT g_EncryptSize = 0;
STATIC BOOL g_ProcKiller = FALSE;

VOID global::SetEncryptMode(INT EncryptMode)
{
	g_EncryptMode = EncryptMode;
}

INT global::GetEncryptMode()
{
	return g_EncryptMode;
}

VOID global::SetEncryptSize(INT Size)
{
	g_EncryptSize = Size;
}

INT global::GetEncryptSize()
{
	return g_EncryptSize;
}

VOID global::SetProcKiller(BOOL IsEnabled)
{
	g_ProcKiller = IsEnabled;
}

BOOL global::GetProcKiller()
{
	return g_ProcKiller;
}

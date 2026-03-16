#pragma once
#include <Windows.h>

// morphcode() - Anti-analysis function
// Generates junk computations using its arguments to hinder
// static and dynamic analysis. The variadic template accepts
// any argument type and performs volatile operations to prevent
// the compiler from optimizing the calls away.

inline void morphcode()
{
	volatile DWORD x = GetTickCount();
	volatile DWORD y = x ^ 0xDEADBEEF;
	(void)y;
}

template<typename T>
inline void morphcode(T arg)
{
	volatile DWORD_PTR x = (DWORD_PTR)arg;
	volatile DWORD_PTR y = x ^ 0xCAFEBABE;
	volatile DWORD_PTR z = y + GetTickCount();
	(void)z;
}

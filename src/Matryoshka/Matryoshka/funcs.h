#pragma once 

#include <Windows.h>

typedef HMODULE(WINAPI* LoadLibrary_T)
(
	PCHAR lpFileName
);

typedef FARPROC(WINAPI* GetLastError_T)();

typedef FARPROC(WINAPI* GetProcAddress_T)
(
	HMODULE hModule,
	PCHAR  lpProcName
);

typedef BOOL(WINAPI* IsBadReadPtr_T)
(
	const VOID* lp,
	UINT_PTR   ucb
);

typedef LPVOID(WINAPI* VirtualAlloc_T)
(
	LPVOID lpAddress,
	SIZE_T dwSize,
	DWORD  flAllocationType,
	DWORD  flProtect
);

typedef FARPROC(WINAPI* VirtualQuery_T)
(
	HMODULE hModule,
	PCHAR  lpProcName
);
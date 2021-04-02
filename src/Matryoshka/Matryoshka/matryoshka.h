#pragma once

#include <Windows.h>

#include "funcs.h"

#define MATRYOSHKA_CONFIG_MAGIC 0xC0FFEE
#define MATRYOSHKA_EGG_MAGIC 0xFEEDFACE

typedef struct {
	DWORD magic;               /// magic bytes used to identify the egg
	DWORD egg_size;            /// size of the included egg/payload
	BYTE stage[];              /// stage to execute
} matryoshka_egg_t;

typedef struct {
	DWORD magic;	   	       /// magic bytes for the configuration file
	BYTE egg_pattern[8];       /// pattern to search for to identify the egg in-memory
} matryoshka_loader_config_t;

typedef struct {
	LoadLibrary_T LoadLibrary;
	GetLastError_T GetLastError;
	GetProcAddress_T GetProcAddress;
	IsBadReadPtr_T IsBadReadPtr;
	VirtualAlloc_T VirtualAlloc;
	VirtualQuery_T VirtualQuery;
} matryoshka_runtime;

typedef struct {
	matryoshka_runtime runtime;
} matryoshka_state;

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
	union {
		WORD bitmap; /// full bitmap of flags
		struct {
			unsigned int spawn_new_thread : 1; /// spawn the second-stage payload in a new thread
			unsigned int reserved2 : 1;        /// TODO: flag to allocate RX instead of RWX memory
			unsigned int reserved3 : 1;        /// TODO: check if process is in high integrity mode and exit
			unsigned int reserved4 : 1;
			unsigned int reserved5 : 1;
			unsigned int reserved6 : 1;
			unsigned int reserved7 : 1;
			unsigned int reserved8 : 1;
			unsigned int reserved9 : 1;
			unsigned int reserved10 : 1;
			unsigned int reserved11 : 1;
			unsigned int reserved12 : 1;
			unsigned int reserved13 : 1;
			unsigned int reserved14 : 1;
			unsigned int reserved15 : 1;
			unsigned int reserved16 : 1;
		};
	};
} matryoshka_loader_flags_t;

typedef struct {
	DWORD magic;	   	                    /// magic bytes for the configuration file
	BYTE egg_pattern[8];                    /// pattern to search for to identify the egg in-memory
	matryoshka_loader_flags_t flags;        /// loader flags used to specify optional loader behavior
} matryoshka_loader_config_t;

typedef struct {
	CreateThread_T CreateThread;
	GetLastError_T GetLastError;
	GetProcAddress_T GetProcAddress;
	IsBadReadPtr_T IsBadReadPtr;
	LoadLibrary_T LoadLibrary;
	VirtualAlloc_T VirtualAlloc;
	VirtualQuery_T VirtualQuery;
} matryoshka_runtime;

typedef struct {
	matryoshka_runtime runtime;
} matryoshka_state;

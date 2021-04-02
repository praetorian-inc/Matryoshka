/**
 * @brief Simple debugging tools
 */

#pragma once

#ifdef _DEBUG 
#include <stdio.h>
#define debug(fmt, ...) printf(fmt, __VA_ARGS__) 
#else 
#define debug(fmt, ...) do {} while (0) 
#endif
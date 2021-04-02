#pragma once

#include <Windows.h>

void* crt_memcpy(void* dest, const void* src, unsigned int n)
{
	unsigned long i;
	unsigned char* d = (unsigned char*)dest;
	unsigned char* s = (unsigned char*)src;

	for (i = 0; i < n; ++i) {
		d[i] = s[i];
	}

	return dest;
}

int crt_strcmp(const char* s1, const char* s2) {
	while (*s1 != '\0' && *s2 != '\0' && *s1 == *s2) {
		s1++;
		s2++;
	}
	return *s1 - *s2;
}

int crt_wcscmp(const wchar_t* s1, const wchar_t* s2)
{

	while (*s1 == *s2++)
		if (*s1++ == 0)
			return (0);

	return s1 - --s2;
}
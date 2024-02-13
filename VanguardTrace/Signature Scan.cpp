#include "Include.hpp"

namespace Scanner
{
	BOOLEAN CheckMask(PCHAR base, PCHAR pattern, PCHAR mask)
	{
		for (; *mask; ++base, ++pattern, ++mask)
		{
			if (*mask == 'x' && *base != *pattern)
			{
				return FALSE;
			}
		}

		return TRUE;
	}

	PVOID FindPattern(PCHAR base, DWORD length, PCHAR pattern, PCHAR mask)
	{
		length -= (DWORD)strlen(mask);

		for (DWORD i = 0; i <= length; ++i)
		{
			PVOID addr = &base[i];
			if (CheckMask((PCHAR)addr, pattern, mask))
			{
				return addr;
			}
		}

		return 0;
	}

	PVOID FindPatternImage(PCHAR base, PCHAR pattern, PCHAR mask)
	{
		PVOID match = 0;

		PIMAGE_NT_HEADERS headers = (PIMAGE_NT_HEADERS)(base + ((PIMAGE_DOS_HEADER)base)->e_lfanew);
		PIMAGE_SECTION_HEADER sections = IMAGE_FIRST_SECTION(headers);

		for (DWORD i = 0; i < headers->FileHeader.NumberOfSections; ++i)
		{
			PIMAGE_SECTION_HEADER section = &sections[i];

			if (memcmp(section->Name, ".text", 5) == 0)
			{
				match = FindPattern(base + section->VirtualAddress, section->Misc.VirtualSize, pattern, mask);
				if (match)
				{
					break;
				}
			}
		}

		return match;
	}

	PVOID FindPatternImageExec(PCHAR base, PCHAR pattern, PCHAR mask)
	{
		PVOID match = 0;

		PIMAGE_NT_HEADERS headers = (PIMAGE_NT_HEADERS)(base + ((PIMAGE_DOS_HEADER)base)->e_lfanew);
		PIMAGE_SECTION_HEADER sections = IMAGE_FIRST_SECTION(headers);

		for (DWORD i = 0; i < headers->FileHeader.NumberOfSections; ++i)
		{
			PIMAGE_SECTION_HEADER section = &sections[i];

			if (*(PINT)section->Name == 'EGAP' || memcmp(section->Name, ".text", 5) == 0)
			{
				match = FindPattern(base + section->VirtualAddress, section->Misc.VirtualSize, pattern, mask);
				if (match)
				{
					break;
				}
			}
		}

		return match;
	}
}

#pragma once

namespace Scanner 
{
	PVOID FindPatternImage(PCHAR base, PCHAR pattern, PCHAR mask);
	PVOID FindPatternImageExec(PCHAR base, PCHAR pattern, PCHAR mask);
	PVOID FindPattern(PCHAR base, DWORD length, PCHAR pattern, PCHAR mask);
}
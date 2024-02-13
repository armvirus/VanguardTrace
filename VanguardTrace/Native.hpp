#pragma once

extern "C" 
{
	NTSTATUS NTAPI ZwQuerySystemInformation(ULONG SystemInformationClass, PVOID SystemInformation,
		ULONG SystemInformationLength, PULONG ReturnLength);

	extern "C" NTKERNELAPI
		PVOID
		NTAPI
		RtlFindExportedRoutineByName(
			_In_ PVOID ImageBase,
			_In_ PCCH RoutineNam
		);
}

namespace Native 
{
	NTSTATUS getKernelModuleByName(const char *moduleName, std::uintptr_t *moduleStart, std::size_t *moduleSize);
}

typedef struct _SYSTEM_MODULE_ENTRY {
	HANDLE Section;
	PVOID MappedBase;
	PVOID ImageBase;
	ULONG ImageSize;
	ULONG Flags;
	USHORT LoadOrderIndex;
	USHORT InitOrderIndex;
	USHORT LoadCount;
	USHORT OffsetToFileName;
	UCHAR FullPathName[256];
} SYSTEM_MODULE_ENTRY, * PSYSTEM_MODULE_ENTRY;

typedef struct _SYSTEM_MODULE_INFORMATION {
	ULONG Count;
	SYSTEM_MODULE_ENTRY Module[1];
} SYSTEM_MODULE_INFORMATION, * PSYSTEM_MODULE_INFORMATION;
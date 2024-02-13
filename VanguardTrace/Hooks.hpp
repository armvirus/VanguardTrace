#pragma once

namespace Hooks
{
    inline NTSTATUS(*CiCheckSignedFileOg)(void* Buf1, size_t Size, unsigned int a3, __int64 a4, unsigned int a5, __int64 a6, __int64* a7, __int64* a8);

	NTSTATUS CiCheckSignedFileHookVgk(void* Buf1, size_t Size, unsigned int a3, __int64 a4, unsigned int a5, __int64 a6, __int64* a7, __int64* a8);
    NTSTATUS ZwDeviceIoControlFileHook(HANDLE FileHandle, HANDLE Event, PIO_APC_ROUTINE ApcRoutine, PVOID ApcContext, PIO_STATUS_BLOCK IoStatusBlock, ULONG IoControlCode, PVOID InputBuffer, ULONG InputBufferLength, PVOID OutputBuffer, ULONG OutputBufferLength);
}
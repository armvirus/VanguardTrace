#include "Include.hpp"

namespace Hooks
{
    NTSTATUS CiCheckSignedFileHookVgk(void* Buf1, size_t Size, unsigned int a3, __int64 a4, unsigned int a5, __int64 a6, __int64* a7, __int64* a8)
    {
        auto ret = CiCheckSignedFileOg(Buf1, Size, a3, a4, a5, a6, a7, a8);

        DebugPrint("[%p] CiCheckSignedFile Called with Buf %p\n", _ReturnAddress(), Buf1);

        return ret == STATUS_INVALID_IMAGE_HASH ? STATUS_SUCCESS : ret;
    }

    NTSTATUS ZwDeviceIoControlFileHook(HANDLE FileHandle, HANDLE Event, PIO_APC_ROUTINE ApcRoutine, PVOID ApcContext, PIO_STATUS_BLOCK IoStatusBlock, ULONG IoControlCode, PVOID InputBuffer, ULONG InputBufferLength, PVOID OutputBuffer, ULONG OutputBufferLength)
    {
        DebugPrint("ZwDeviceIoControlFile Called From 0x%p\n", _ReturnAddress());
        DebugPrint("     - IoControlCode: 0x%p\n", IoControlCode);

        return ZwDeviceIoControlFile(FileHandle, Event, ApcRoutine, ApcContext, IoStatusBlock, IoControlCode, InputBuffer, InputBufferLength, OutputBuffer, OutputBufferLength);
    }

}
#include "Include.hpp"

NTSTATUS DriverEntry(const PDRIVER_OBJECT driverObject, const PUNICODE_STRING registryPath)
{
    DebugPrint("Vanguard Trace Hook Initiating...\n");

    std::uintptr_t moduleBase = 0;
    std::size_t moduleSize = 0;

    if (Native::getKernelModuleByName("vgk.sys", &moduleBase, &moduleSize))
        return STATUS_NOT_FOUND;

    std::uint32_t startOffset = Vanguard::getImportStartOffset(moduleBase, moduleSize); // 0x816a0;

    DebugPrint("Found startOffset @ 0x%x", startOffset);

    std::uint32_t ExCreateCallbackOffset = Vanguard::findImportOffset(moduleBase, "ntoskrnl.exe", "ExCreateCallback", startOffset);

    DebugPrint("Found ExCreateCallbackOffset @ 0x%x", ExCreateCallbackOffset);

    std::uint32_t CiCheckSignedFileOffset = Vanguard::findImportOffset(moduleBase, "CI.dll", "CiCheckSignedFile", startOffset);

    DebugPrint("Found CiCheckSignedFileOffset @ 0x%x", CiCheckSignedFileOffset);

    *reinterpret_cast<std::uintptr_t*>(&Hooks::CiCheckSignedFileOg) = Vanguard::DecryptVGKImportFunction(moduleBase, CiCheckSignedFileOffset);

    Vanguard::HookVgkImportFunction(moduleBase, CiCheckSignedFileOffset, reinterpret_cast<std::uintptr_t>(&Hooks::CiCheckSignedFileHookVgk));

    return STATUS_SUCCESS;
}
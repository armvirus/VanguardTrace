#pragma once

struct KeyOffsets {
    __int64 wordOffset;  // Previously key1
    __int64 qwordPtrOffset; // Previously key2
    __int64 qwordOffset; // Previously key3
    __int64 byteCountOffset; // Previously key4
};

namespace Vanguard
{
    void HookVgkImportFunction(std::uintptr_t VanguardBase, std::uintptr_t ImportOffset, std::uintptr_t originalFunctionPtr);
    std::uintptr_t DecryptVGKImportFunction(std::uintptr_t VanguardBase, std::uintptr_t ImportOffset);
    std::uint32_t findImportOffset(std::uintptr_t VanguardBase, const char* ImportModule, const char* ImportName, std::uint32_t startOffset);
    std::uint32_t getImportStartOffset(std::uintptr_t VanguardBase, std::size_t VanguardSize);
}
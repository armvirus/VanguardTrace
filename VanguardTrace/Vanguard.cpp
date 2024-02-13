#include "Include.hpp"

namespace Vanguard
{
    void HookVgkImportFunction(std::uintptr_t VanguardBase, std::uintptr_t ImportOffset, std::uintptr_t originalFunctionPtr)
    {
        if (!VanguardBase || !ImportOffset || !originalFunctionPtr)
            return;

        KeyOffsets offsets = {
            ImportOffset,
            ImportOffset + 0x8,
            ImportOffset + 0x18,
            ImportOffset + 0x20
        };

        // Retrieve the original values from the offsets
        uintptr_t& wordAtKey1 = *reinterpret_cast<uintptr_t*>(VanguardBase + offsets.wordOffset);
        uintptr_t& functionXor = *reinterpret_cast<uintptr_t*>(VanguardBase + offsets.qwordPtrOffset + 8 * HIBYTE(wordAtKey1));
        uintptr_t& byteCount = *reinterpret_cast<uintptr_t*>(VanguardBase + offsets.byteCountOffset);
        unsigned char byteCountValue = static_cast<unsigned char>(byteCount);

        // Reverse the XOR operations for the byteCount part
        if (HIBYTE(byteCount) > 0) {
            uintptr_t valueAtKey3 = *reinterpret_cast<uintptr_t*>(VanguardBase + offsets.qwordOffset);
            for (size_t i = 8 - HIBYTE(byteCount); i < 8; ++i) {
                reinterpret_cast<uint8_t*>(&originalFunctionPtr)[i] ^= reinterpret_cast<uint8_t*>(valueAtKey3)[i];
            }
        }

        // Reverse the XOR operations for the main encryption loop
        for (int8_t i = byteCountValue - 1; i >= 0; --i) {
            uintptr_t xorValue = *reinterpret_cast<uintptr_t*>(VanguardBase + offsets.qwordOffset + 8 * (i & 0xFF));
            originalFunctionPtr ^= xorValue;
        }

        // Overwrite the original function pointer with the encrypted value
        functionXor = originalFunctionPtr;
    }

    std::uintptr_t DecryptVGKImportFunction(std::uintptr_t VanguardBase, std::uintptr_t ImportOffset)
    {
        if (!VanguardBase || !ImportOffset)
            return 0;

        KeyOffsets offsets = {
        ImportOffset,
        ImportOffset + 0x8,
        ImportOffset + 0x18,
        ImportOffset + 0x20
        };

        uintptr_t wordAtKey1 = *reinterpret_cast<uintptr_t*>(VanguardBase + offsets.wordOffset);
        if (!wordAtKey1)
            return 0;

        uintptr_t functionXor = *reinterpret_cast<__int64*>(VanguardBase + offsets.qwordPtrOffset + 8 * HIBYTE(wordAtKey1));
        if (!functionXor)
            return 0;

        uintptr_t byteCount = *reinterpret_cast<uintptr_t*>(VanguardBase + offsets.byteCountOffset);
        if (byteCount != 1)
            return 0;

        unsigned char byteCountValue = static_cast<unsigned char>(byteCount);

        for (uint8_t i = 0; i < byteCountValue; ++i) {
            uintptr_t xorValue = *reinterpret_cast<uintptr_t*>(VanguardBase + offsets.qwordOffset + 8 * (i & 0xFF));
            functionXor ^= xorValue;
        }

        if (HIBYTE(byteCount) > 0)
        {
            uintptr_t valueAtKey3 = *reinterpret_cast<uintptr_t*>(VanguardBase + offsets.qwordOffset);

            for (size_t i = 8 - HIBYTE(byteCount); i < 8; ++i) {
                reinterpret_cast<uint8_t*>(&functionXor)[i] ^= reinterpret_cast<uint8_t*>(valueAtKey3)[i];
            }
        }

        return functionXor;
    }

    std::uint32_t getImportStartOffset(std::uintptr_t VanguardBase, std::size_t VanguardSize)
    {
        if (!VanguardBase || !VanguardSize)
            return 0;

        // [actual address in first opcode] 66 0F AB D3 44 38 1D ? ? ? ?
        // 66 C7 05 ? ? ? ? ? ? 48 63 D5 
        // 4C 8D 05 ? ? ? ? 48 0F B7 CA

        std::uintptr_t leaStartOffset = reinterpret_cast<std::uintptr_t>(Scanner::FindPattern(reinterpret_cast<char*>(VanguardBase), VanguardSize, "\x8A\x15\x00\x00\x00\x00\xE9\x00\x00\x00\x00\x48\x98", "xx????x????xx"));
        if (!leaStartOffset || !MmIsAddressValid(reinterpret_cast<void*>(leaStartOffset)))
            return 0;

        std::uintptr_t startOffset = RVA(leaStartOffset, 6);
        if (!startOffset || !MmIsAddressValid(reinterpret_cast<void*>(startOffset)))
            return 0;

        std::uint32_t randomOffset = startOffset - VanguardBase - 1;

        std::uint32_t firstImport = 0;
        for (int i = 0;; i++)
        {
            std::uint32_t Offset = randomOffset - i * 0x28;
            std::uintptr_t DecryptedRoutine = Vanguard::DecryptVGKImportFunction(VanguardBase, Offset);
            if (!DecryptedRoutine || !MmIsAddressValid(reinterpret_cast<void*>(DecryptedRoutine)))
                break;

            firstImport = Offset;
        }

        return firstImport;
    }

    std::uint32_t findImportOffset(std::uintptr_t VanguardBase, const char* ImportModule, const char* ImportName, std::uint32_t startOffset)
    {
        if (!VanguardBase || !startOffset)
            return 0;

        std::uintptr_t importModuleBase{};
        std::size_t importModuleSize{};

        if (!NT_SUCCESS(Native::getKernelModuleByName(ImportModule, &importModuleBase, &importModuleSize)))
            return 0;

        std::uintptr_t importAddress = reinterpret_cast<std::uintptr_t>(RtlFindExportedRoutineByName(reinterpret_cast<void*>(importModuleBase), ImportName));
        if (!importAddress)
            return 0;

        for (int i = 0; ; i++)
        {
            std::uint32_t Offset = startOffset + i * 0x28;
            std::uintptr_t DecryptedRoutine = Vanguard::DecryptVGKImportFunction(VanguardBase, Offset);
            if (!DecryptedRoutine || !MmIsAddressValid(reinterpret_cast<void*>(DecryptedRoutine)))
                break;

            if (importAddress == DecryptedRoutine)
                return Offset;      
        }
          
        return 0;
    }
}
#pragma once

#include <ntifs.h>
#include <windef.h>

#include <ntimage.h>
#include <cstdint>
#include <cstddef>

#include "Native.hpp"
#include "Signature Scan.hpp"
#include "Vanguard.hpp"
#include "Hooks.hpp"

#define RVA(Instr, InstrSize) ((ULONG64)Instr + InstrSize + *(LONG*)((ULONG64)Instr + (InstrSize - sizeof(LONG))))
#define DebugPrint(fmt, ...) DbgPrintEx(0, 0, "[VanguardStackTrace] " fmt, ##__VA_ARGS__)
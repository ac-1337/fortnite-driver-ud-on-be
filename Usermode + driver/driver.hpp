#pragma once
#include <iostream>
#include <Windows.h>
#include <TlHelp32.h>
#include <map>
#include <array>
#include "driver_structs.hpp"
#pragma comment(lib, "Advapi32.lib")

using namespace std;

ULONG ProcessId;
DWORD64 process_base;

bool once = true;

HKEY hKey = NULL;

void Request(uint32_t type, void* instruction) {
	 
	if (once)
	{
		once = false;
		RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\IdentityCRL", 0, KEY_ALL_ACCESS, &hKey);
	}

	if (hKey == NULL || hKey == INVALID_HANDLE_VALUE) {
		return;
	}

	KERNEL_REQUEST request;

	request.Type = type;
	request.Instruction = instruction;

	void* ptr = &request;

	RegSetValueExA(hKey, "DEBRABEUDHA", 0, REG_QWORD, reinterpret_cast<BYTE*>(&ptr), sizeof(uint64_t));
}

template<typename T>
T Read(uint64_t address) {
	T result{};

	KERNEL_COPY_REQUEST request;

	request.ProcessId = ProcessId;
	request.Source = reinterpret_cast<void*>(address);
	request.Destination = &result;
	request.Size = sizeof(T);

	Request(0, &request);

	return result;
}

void ReadRaw(uint64_t address, void* dest, uint32_t size) {

	KERNEL_COPY_REQUEST request;

	request.ProcessId = ProcessId;
	request.Source = reinterpret_cast<void*>(address);
	request.Destination = dest;
	request.Size = size;

	Request(0, &request);
}

void WriteMemory(uint64_t address, void* value, size_t size) {
	KERNEL_COPY_REQUEST request;

	request.ProcessId = ProcessId;
	request.Source = value;
	request.Destination = reinterpret_cast<void*>(address);
	request.Size = size;

	Request(1, &request);
}

template<typename T>
void Write(uint64_t address, T value) {
	WriteMemory(address, &value, sizeof(T));
}

uint64_t GetProcessBase() {
	KERNEL_BASE_REQUEST request;

	request.ProcessId = ProcessId;
	request.ProcessBase = 0;

	Request(3, &request);

	return request.ProcessBase;
}

std::uintptr_t scan_pattern(const char* sig, const char* mask)
{
	auto buffer = std::make_unique<std::array<std::uint8_t, 0x100000>>();
	auto data = buffer.get()->data();

	for (std::uintptr_t i = 0u; i < (2u << 25u); ++i)
	{
		ReadRaw(GetProcessBase() + i * 0x100000, data, 0x100000);

		if (!data)
			return 0;

		for (std::uintptr_t j = 0; j < 0x100000u; ++j)
		{
			if ([](std::uint8_t const* data, std::uint8_t const* sig, char const* mask)
				{
					for (; *mask; ++mask, ++data, ++sig)
					{
						if (*mask == 'x' && *data != *sig) return false;
					}
					return (*mask) == 0;
				}(data + j, (std::uint8_t*)sig, mask))
			{
				std::uintptr_t result = GetProcessBase() + i * 0x100000 + j;
				std::uint32_t rel = 0;

				ReadRaw(result + 3, &rel, sizeof(std::uint32_t));

				if (!rel)
					return 0;

				return result + rel + 7;
			}
		}
	}

	return 0;
}
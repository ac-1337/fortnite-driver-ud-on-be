#include <iostream>
#include <Windows.h>
#include <tchar.h>

#include "driver.hpp"
#include "process.hpp"

bool initdrv() {

	ProcessId = GetProcessID(_T("notepad.exe"));

	while (!ProcessId) {
		ProcessId = GetProcessID(_T("notepad.exe"));
	}

	std::cout << "Process ID: " << ProcessId << "\n";

	while (!process_base) {
		process_base = GetProcessBase();
	}

	std::cout << "Base Address: " << (void*)process_base << "\n";

	return true;
}

bool rpm() {
	uintptr_t addr_read =  Read<uintptr_t>(process_base);
	std::cout << "Read: " << addr_read << "\n";
	Sleep(1000);
	return true;
}

int main()
{
	start_service();

	initdrv();

	while (true)
	{
		rpm();
	}
	return 0;
}
#pragma once
#ifndef UM_Utilities_HEADER_INCLUDED
#define UM_Utilities_HEADER_INCLUDED

#include "..\both\GeneralErrors.h"

#pragma comment(lib, "ntdll.lib")
#pragma comment(lib, "kernel32.lib")



static GeneralErrorCast FindProcessByNameA(const char* ProcessName, PROCESSENTRY32* Process)
{
	if (!ProcessName)
		return GENERAL_ERROR_ASSEMBLE(GENERAL_ERROR_HEADER_UM_UTILITIES, STATUS_INVALID_PARAMETER_1) | 1;

	if (!Process)
		return GENERAL_ERROR_ASSEMBLE(GENERAL_ERROR_HEADER_UM_UTILITIES, STATUS_INVALID_PARAMETER_2) | 1;

	memset(Process, 0, sizeof(PROCESSENTRY32));

	PROCESSENTRY32 ProcessEntry;
	HANDLE SnapShot;

	ProcessEntry.dwSize = sizeof(ProcessEntry);
	SnapShot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (!SnapShot || SnapShot == INVALID_HANDLE_VALUE)
		return GENERAL_ERROR_ASSEMBLE(GENERAL_ERROR_HEADER_UM_UTILITIES, NTSTATUS_FROM_WIN32(GetLastError())) | 1;

	if (!Process32First(SnapShot, &ProcessEntry))
	{
		CloseHandle(SnapShot);
		return GENERAL_ERROR_ASSEMBLE(GENERAL_ERROR_HEADER_UM_UTILITIES, NTSTATUS_FROM_WIN32(GetLastError())) | 1;
	}
	do
	{
		if (!_stricmp(ProcessEntry.szExeFile, ProcessName))
		{
			memcpy(Process, &ProcessEntry, sizeof(ProcessEntry));
			CloseHandle(SnapShot);
			return STATUS_SUCCESS;
		}
	} while (Process32Next(SnapShot, &ProcessEntry));
	CloseHandle(SnapShot);
	return GENERAL_ERROR_ASSEMBLE(GENERAL_ERROR_HEADER_UM_UTILITIES, NTSTATUS_FROM_WIN32(GetLastError())) | 1;
}

static GeneralErrorCast FindProcessByNameW(const wchar_t* ProcessName, PROCESSENTRY32W* Process)
{
	if (!ProcessName)
		return GENERAL_ERROR_ASSEMBLE(GENERAL_ERROR_HEADER_UM_UTILITIES, STATUS_INVALID_PARAMETER_1) | 1;

	if (!Process)
		return GENERAL_ERROR_ASSEMBLE(GENERAL_ERROR_HEADER_UM_UTILITIES, STATUS_INVALID_PARAMETER_2) | 1;

	memset(Process, 0, sizeof(PROCESSENTRY32W));

	PROCESSENTRY32W ProcessEntry;
	HANDLE SnapShot;

	ProcessEntry.dwSize = sizeof(ProcessEntry);
	SnapShot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (!SnapShot || SnapShot == INVALID_HANDLE_VALUE)
		return GENERAL_ERROR_ASSEMBLE(GENERAL_ERROR_HEADER_UM_UTILITIES, NTSTATUS_FROM_WIN32(GetLastError())) | 1;

	if (!Process32FirstW(SnapShot, &ProcessEntry))
	{
		CloseHandle(SnapShot);
		return GENERAL_ERROR_ASSEMBLE(GENERAL_ERROR_HEADER_UM_UTILITIES, NTSTATUS_FROM_WIN32(GetLastError())) | 1;
	}
	do
	{
		if (!_wcsicmp(ProcessEntry.szExeFile, ProcessName))
		{
			memcpy(Process, &ProcessEntry, sizeof(ProcessEntry));
			CloseHandle(SnapShot);
			return TRUE;
		}
	} while (Process32NextW(SnapShot, &ProcessEntry));
	CloseHandle(SnapShot);
	return GENERAL_ERROR_ASSEMBLE(GENERAL_ERROR_HEADER_UM_UTILITIES, NTSTATUS_FROM_WIN32(GetLastError())) | 1;
}

static GeneralErrorCast FindProcessByProcessIDA(unsigned long ProcessID, PROCESSENTRY32* Process)
{
	if (!Process)
		return GENERAL_ERROR_ASSEMBLE(GENERAL_ERROR_HEADER_UM_UTILITIES, STATUS_INVALID_PARAMETER_2) | 1;

	memset(Process, 0, sizeof(PROCESSENTRY32));

	PROCESSENTRY32 ProcessEntry;
	HANDLE SnapShot;

	ProcessEntry.dwSize = sizeof(ProcessEntry);
	SnapShot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (!SnapShot || SnapShot == INVALID_HANDLE_VALUE)
		return GENERAL_ERROR_ASSEMBLE(GENERAL_ERROR_HEADER_UM_UTILITIES, NTSTATUS_FROM_WIN32(GetLastError())) | 1;

	if (!Process32First(SnapShot, &ProcessEntry))
	{
		CloseHandle(SnapShot);
		return GENERAL_ERROR_ASSEMBLE(GENERAL_ERROR_HEADER_UM_UTILITIES, NTSTATUS_FROM_WIN32(GetLastError())) | 1;
	}
	do
	{
		if (ProcessEntry.th32ProcessID == ProcessID)
		{
			memcpy(Process, &ProcessEntry, sizeof(ProcessEntry));
			CloseHandle(SnapShot);
			return TRUE;
		}
	} while (Process32Next(SnapShot, &ProcessEntry));
	CloseHandle(SnapShot);
	return GENERAL_ERROR_ASSEMBLE(GENERAL_ERROR_HEADER_UM_UTILITIES, NTSTATUS_FROM_WIN32(GetLastError())) | 1;
}

static GeneralErrorCast FindProcessByProcessIDW(unsigned long ProcessID, PROCESSENTRY32W* Process)
{
	if (!Process)
		return GENERAL_ERROR_ASSEMBLE(GENERAL_ERROR_HEADER_UM_UTILITIES, STATUS_INVALID_PARAMETER_2) | 1;

	memset(Process, 0, sizeof(PROCESSENTRY32W));

	PROCESSENTRY32W ProcessEntry;
	HANDLE SnapShot;

	ProcessEntry.dwSize = sizeof(ProcessEntry);
	SnapShot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (!SnapShot || SnapShot == INVALID_HANDLE_VALUE)
		return GENERAL_ERROR_ASSEMBLE(GENERAL_ERROR_HEADER_UM_UTILITIES, NTSTATUS_FROM_WIN32(GetLastError())) | 1;

	if (!Process32FirstW(SnapShot, &ProcessEntry))
	{
		CloseHandle(SnapShot);
		return GENERAL_ERROR_ASSEMBLE(GENERAL_ERROR_HEADER_UM_UTILITIES, NTSTATUS_FROM_WIN32(GetLastError())) | 1;
	}
	do
	{
		if (ProcessEntry.th32ProcessID == ProcessID)
		{
			memcpy(Process, &ProcessEntry, sizeof(ProcessEntry));
			CloseHandle(SnapShot);
			return TRUE;
		}
	} while (Process32NextW(SnapShot, &ProcessEntry));
	CloseHandle(SnapShot);
	return GENERAL_ERROR_ASSEMBLE(GENERAL_ERROR_HEADER_UM_UTILITIES, NTSTATUS_FROM_WIN32(GetLastError())) | 1;
}

static GeneralErrorCast FindProcessModuleByNameA(unsigned long ProcessID, const char* ModuleName, MODULEENTRY32* Module)
{
	if (!ModuleName)
		return GENERAL_ERROR_ASSEMBLE(GENERAL_ERROR_HEADER_UM_UTILITIES, STATUS_INVALID_PARAMETER_2) | 1;

	if (!Module)
		return GENERAL_ERROR_ASSEMBLE(GENERAL_ERROR_HEADER_UM_UTILITIES, STATUS_INVALID_PARAMETER_3) | 1;

	memset(Module, 0, sizeof(MODULEENTRY32));

	HANDLE SnapShot;
	MODULEENTRY32 ModuleEntry;

	ModuleEntry.dwSize = sizeof(ModuleEntry);
	SnapShot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, ProcessID);
	if (!SnapShot || SnapShot == INVALID_HANDLE_VALUE)
		return GENERAL_ERROR_ASSEMBLE(GENERAL_ERROR_HEADER_UM_UTILITIES, NTSTATUS_FROM_WIN32(GetLastError())) | 1;

	if (!Module32First(SnapShot, &ModuleEntry))
	{
		CloseHandle(SnapShot);
		return GENERAL_ERROR_ASSEMBLE(GENERAL_ERROR_HEADER_UM_UTILITIES, NTSTATUS_FROM_WIN32(GetLastError())) | 1;
	}
	do
	{
		if (!_stricmp(ModuleEntry.szModule, ModuleName))
		{
			memcpy(Module, &ModuleEntry, sizeof(ModuleEntry));
			CloseHandle(SnapShot);
			return TRUE;
		}
	} while (Module32Next(SnapShot, &ModuleEntry));
	CloseHandle(SnapShot);
	return GENERAL_ERROR_ASSEMBLE(GENERAL_ERROR_HEADER_UM_UTILITIES, NTSTATUS_FROM_WIN32(GetLastError())) | 1;
}

static GeneralErrorCast FindProcessModuleByNameW(unsigned long ProcessID, const wchar_t* ModuleName, MODULEENTRY32W* Module)
{
	if (!ModuleName)
		return GENERAL_ERROR_ASSEMBLE(GENERAL_ERROR_HEADER_UM_UTILITIES, STATUS_INVALID_PARAMETER_2) | 1;

	if (!Module)
		return GENERAL_ERROR_ASSEMBLE(GENERAL_ERROR_HEADER_UM_UTILITIES, STATUS_INVALID_PARAMETER_3) | 1;

	memset(Module, 0, sizeof(MODULEENTRY32W));

	HANDLE SnapShot;
	MODULEENTRY32W ModuleEntry;

	ModuleEntry.dwSize = sizeof(ModuleEntry);
	SnapShot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, ProcessID);
	if (!SnapShot || SnapShot == INVALID_HANDLE_VALUE)
		return GENERAL_ERROR_ASSEMBLE(GENERAL_ERROR_HEADER_UM_UTILITIES, NTSTATUS_FROM_WIN32(GetLastError())) | 1;

	if (!Module32FirstW(SnapShot, &ModuleEntry))
	{
		CloseHandle(SnapShot);
		return GENERAL_ERROR_ASSEMBLE(GENERAL_ERROR_HEADER_UM_UTILITIES, NTSTATUS_FROM_WIN32(GetLastError())) | 1;
	}
	do
	{
		if (!_wcsicmp(ModuleEntry.szModule, ModuleName))
		{
			memcpy(Module, &ModuleEntry, sizeof(ModuleEntry));
			CloseHandle(SnapShot);
			return TRUE;
		}
	} while (Module32NextW(SnapShot, &ModuleEntry));
	CloseHandle(SnapShot);
	return GENERAL_ERROR_ASSEMBLE(GENERAL_ERROR_HEADER_UM_UTILITIES, NTSTATUS_FROM_WIN32(GetLastError())) | 1;
}

static GeneralErrorCast FindThreadByID(unsigned long ThreadID, THREADENTRY32* Thread)
{
	if (!Thread)
		return GENERAL_ERROR_ASSEMBLE(GENERAL_ERROR_HEADER_UM_UTILITIES, STATUS_INVALID_PARAMETER_2) | 1;

	memset(Thread, 0, sizeof(THREADENTRY32));

	THREADENTRY32 ThreadEntry;
	HANDLE SnapShot;

	ThreadEntry.dwSize = sizeof(ThreadEntry);
	SnapShot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
	if (!SnapShot || SnapShot == INVALID_HANDLE_VALUE)
		return GENERAL_ERROR_ASSEMBLE(GENERAL_ERROR_HEADER_UM_UTILITIES, NTSTATUS_FROM_WIN32(GetLastError())) | 1;

	if (!Thread32First(SnapShot, &ThreadEntry))
	{
		CloseHandle(SnapShot);
		return GENERAL_ERROR_ASSEMBLE(GENERAL_ERROR_HEADER_UM_UTILITIES, NTSTATUS_FROM_WIN32(GetLastError())) | 1;
	}
	do
	{
		if (ThreadEntry.th32ThreadID == ThreadID)
		{
			memcpy(Thread, &ThreadEntry, sizeof(ThreadEntry));
			CloseHandle(SnapShot);
			return TRUE;
		}
	} while (Thread32Next(SnapShot, &ThreadEntry));
	CloseHandle(SnapShot);
	return GENERAL_ERROR_ASSEMBLE(GENERAL_ERROR_HEADER_UM_UTILITIES, NTSTATUS_FROM_WIN32(GetLastError())) | 1;
}

static GeneralErrorCast GetThreadWin32Start(unsigned long ThreadID, void** Win32Start)
{
	if (!Win32Start)
		return GENERAL_ERROR_ASSEMBLE(GENERAL_ERROR_HEADER_UM_UTILITIES, STATUS_INVALID_PARAMETER_2) | 1;

	HANDLE ThreadHandle;
	NTSTATUS Status;

	unsigned long ReturnLenght;

	ThreadHandle = OpenThread(THREAD_QUERY_INFORMATION, FALSE, ThreadID);
	if (ThreadHandle == INVALID_HANDLE_VALUE)
		return GENERAL_ERROR_ASSEMBLE(GENERAL_ERROR_HEADER_UM_UTILITIES, NTSTATUS_FROM_WIN32(GetLastError())) | 1;

	Status = NtQueryInformationThread(ThreadHandle, (THREADINFOCLASS)9, Win32Start, sizeof(*Win32Start), &ReturnLenght);
	if (!NT_SUCCESS(Status))
	{
		CloseHandle(ThreadHandle);
		return GENERAL_ERROR_ASSEMBLE(GENERAL_ERROR_HEADER_UM_UTILITIES, Status) | 1;
	}
	if (ReturnLenght != sizeof(void*))
	{
		CloseHandle(ThreadHandle);
		return GENERAL_ERROR_ASSEMBLE(GENERAL_ERROR_HEADER_UM_UTILITIES, STATUS_PARTIAL_COPY) | 1;
	}

	CloseHandle(ThreadHandle);
	return STATUS_SUCCESS;
}

static GeneralErrorCast FindThreadByWin32Start(void* ThreadStart, THREADENTRY32* Thread)
{
	if (!ThreadStart)
		return GENERAL_ERROR_ASSEMBLE(GENERAL_ERROR_HEADER_UM_UTILITIES, STATUS_INVALID_PARAMETER_1) | 1;

	if (!Thread)
		return GENERAL_ERROR_ASSEMBLE(GENERAL_ERROR_HEADER_UM_UTILITIES, STATUS_INVALID_PARAMETER_2) | 1;

	memset(Thread, 0, sizeof(THREADENTRY32));

	THREADENTRY32 ThreadEntry;
	HANDLE SnapShot;
	HANDLE ThreadHandle;
	void* Win32Start;
	unsigned long ReturnLenght;
	NTSTATUS Status;

	ThreadEntry.dwSize = sizeof(ThreadEntry);
	SnapShot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
	if (!SnapShot || SnapShot == INVALID_HANDLE_VALUE)
		return GENERAL_ERROR_ASSEMBLE(GENERAL_ERROR_HEADER_UM_UTILITIES, NTSTATUS_FROM_WIN32(GetLastError())) | 1;

	if (!Thread32First(SnapShot, &ThreadEntry))
	{
		CloseHandle(SnapShot);
		return GENERAL_ERROR_ASSEMBLE(GENERAL_ERROR_HEADER_UM_UTILITIES, NTSTATUS_FROM_WIN32(GetLastError())) | 1;
	}
	do
	{
		ThreadHandle = OpenThread(THREAD_QUERY_INFORMATION, 0, ThreadEntry.th32ThreadID);
		if (ThreadHandle && ThreadHandle != INVALID_HANDLE_VALUE)
		{
			Status = NtQueryInformationThread(ThreadHandle, (THREADINFOCLASS)9, &Win32Start, sizeof(Win32Start), &ReturnLenght);
			if (NT_SUCCESS(Status))
			{
				if (Win32Start == ThreadStart && ReturnLenght == sizeof(void*))
				{
					memcpy(Thread, &ThreadEntry, sizeof(ThreadEntry));
					CloseHandle(SnapShot);
					CloseHandle(ThreadHandle);
					return TRUE;
				}
			}
			CloseHandle(ThreadHandle);
		}
	} while (Thread32Next(SnapShot, &ThreadEntry));
	CloseHandle(SnapShot);
	return GENERAL_ERROR_ASSEMBLE(GENERAL_ERROR_HEADER_UM_UTILITIES, NTSTATUS_FROM_WIN32(GetLastError())) | 1;
}

static GeneralErrorCast FindProcessThreadByWin32Start(unsigned long ProcessID, void* ThreadStart, THREADENTRY32* Thread)
{
	if (!ThreadStart)
		return GENERAL_ERROR_ASSEMBLE(GENERAL_ERROR_HEADER_UM_UTILITIES, STATUS_INVALID_PARAMETER_1) | 1;

	if (!Thread)
		return GENERAL_ERROR_ASSEMBLE(GENERAL_ERROR_HEADER_UM_UTILITIES, STATUS_INVALID_PARAMETER_2) | 1;

	memset(Thread, 0, sizeof(THREADENTRY32));

	THREADENTRY32 ThreadEntry;
	HANDLE SnapShot;
	HANDLE ThreadHandle;
	void* Win32Start;
	unsigned long ReturnLenght;
	NTSTATUS Status;

	ThreadEntry.dwSize = sizeof(ThreadEntry);
	SnapShot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
	if (!SnapShot || SnapShot == INVALID_HANDLE_VALUE)
		return GENERAL_ERROR_ASSEMBLE(GENERAL_ERROR_HEADER_UM_UTILITIES, NTSTATUS_FROM_WIN32(GetLastError())) | 1;

	if (!Thread32First(SnapShot, &ThreadEntry))
	{
		CloseHandle(SnapShot);
		return GENERAL_ERROR_ASSEMBLE(GENERAL_ERROR_HEADER_UM_UTILITIES, NTSTATUS_FROM_WIN32(GetLastError())) | 1;
	}
	do
	{
		ThreadHandle = OpenThread(THREAD_QUERY_INFORMATION, 0, ThreadEntry.th32ThreadID);
		if (ThreadHandle && ThreadHandle != INVALID_HANDLE_VALUE)
		{
			Status = NtQueryInformationThread(ThreadHandle, (THREADINFOCLASS)9, &Win32Start, sizeof(Win32Start), &ReturnLenght);
			if (NT_SUCCESS(Status))
			{
				if (Win32Start == ThreadStart && ThreadEntry.th32OwnerProcessID == ProcessID && ReturnLenght == sizeof(void*))
				{
					memcpy(Thread, &ThreadEntry, sizeof(ThreadEntry));
					CloseHandle(SnapShot);
					CloseHandle(ThreadHandle);
					return TRUE;
				}
			}
			CloseHandle(ThreadHandle);
		}
	} while (Thread32Next(SnapShot, &ThreadEntry));
	CloseHandle(SnapShot);
	return GENERAL_ERROR_ASSEMBLE(GENERAL_ERROR_HEADER_UM_UTILITIES, NTSTATUS_FROM_WIN32(GetLastError())) | 1;
}

static GeneralErrorCast GetSystemVersion(unsigned long* BuildNumber, unsigned long* MajorVersion, unsigned long* MinorVersion)
{
	if (BuildNumber)
		*BuildNumber = 0;

	if (MajorVersion)
		*MajorVersion = 0;

	if (MinorVersion)
		*MinorVersion = 0;

	char InfoString[10];
	unsigned long InfoSize;
	HKEY RegKey;
	LSTATUS Status;

	Status = RegOpenKeyA(HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion", &RegKey);
	if (Status)
		return GENERAL_ERROR_ASSEMBLE(GENERAL_ERROR_HEADER_UM_UTILITIES, NTSTATUS_FROM_WIN32(Status)) | 1;

	if (BuildNumber)
	{
		InfoSize = sizeof(InfoString);
		Status = RegQueryValueExA(RegKey, "CurrentBuildNumber", 0, 0, (unsigned char*)&InfoString, &InfoSize);
		if (Status)
			return GENERAL_ERROR_ASSEMBLE(GENERAL_ERROR_HEADER_UM_UTILITIES, NTSTATUS_FROM_WIN32(Status)) | 1;

		*BuildNumber = strtoul(InfoString, 0, 10);
	}

	if (MajorVersion)
	{
		InfoSize = sizeof(*MajorVersion);
		Status = RegQueryValueExA(RegKey, "CurrentMajorVersionNumber", 0, 0, (unsigned char*)MajorVersion, &InfoSize);
		if (Status)
			return GENERAL_ERROR_ASSEMBLE(GENERAL_ERROR_HEADER_UM_UTILITIES, NTSTATUS_FROM_WIN32(Status)) | 1;
	}

	if (MinorVersion)
	{
		InfoSize = sizeof(*MinorVersion);
		Status = RegQueryValueExA(RegKey, "CurrentMinorVersionNumber", 0, 0, (unsigned char*)MinorVersion, &InfoSize);
		if (Status)
			return GENERAL_ERROR_ASSEMBLE(GENERAL_ERROR_HEADER_UM_UTILITIES, NTSTATUS_FROM_WIN32(Status)) | 1;
	}

	return TRUE;
}

static GeneralErrorCast FindSystemModuleByNameA(const char* SystemModule, RTL_PROCESS_MODULE_INFORMATION* ModuleInformation)
{
	if (!SystemModule)
		return GENERAL_ERROR_ASSEMBLE(GENERAL_ERROR_HEADER_UM_UTILITIES, STATUS_INVALID_PARAMETER_1) | 1;

	memset(ModuleInformation, 0, sizeof(RTL_PROCESS_MODULE_INFORMATION));

	PRTL_PROCESS_MODULES SystemModules;
	unsigned long InformationDumpSize;

	NtQuerySystemInformation((SYSTEM_INFORMATION_CLASS)11, 0, 0, &InformationDumpSize);
	SystemModules = (PRTL_PROCESS_MODULES)VirtualAlloc(0, InformationDumpSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (!SystemModules)
		return GENERAL_ERROR_ASSEMBLE(GENERAL_ERROR_HEADER_UM_UTILITIES, NTSTATUS_FROM_WIN32(GetLastError())) | 1;

	NtQuerySystemInformation((SYSTEM_INFORMATION_CLASS)11, SystemModules, InformationDumpSize, &InformationDumpSize);

	for (unsigned long i = 0; i < SystemModules->NumberOfModules; i++)
	{
		if (!_stricmp((char*)SystemModules->Modules[i].FullPathName + SystemModules->Modules[i].OffsetToFileName, SystemModule))
		{
			memcpy(ModuleInformation, &SystemModules->Modules[i], sizeof(SystemModules->Modules[i]));
			VirtualFree(SystemModules, 0, MEM_RELEASE);
			return TRUE;
		}
	}

	VirtualFree(SystemModules, 0, MEM_RELEASE);
	return GENERAL_ERROR_ASSEMBLE(GENERAL_ERROR_HEADER_UM_UTILITIES, STATUS_NOT_FOUND) | 1;
}

static GeneralErrorCast FindSystemModuleByNameW(const wchar_t* SystemModule, RTL_PROCESS_MODULE_INFORMATION* ModuleInformation)
{
	if (!SystemModule)
		return GENERAL_ERROR_ASSEMBLE(GENERAL_ERROR_HEADER_UM_UTILITIES, STATUS_INVALID_PARAMETER_1) | 1;

	if (!ModuleInformation)
		return GENERAL_ERROR_ASSEMBLE(GENERAL_ERROR_HEADER_UM_UTILITIES, STATUS_INVALID_PARAMETER_2) | 1;

	memset(ModuleInformation, 0, sizeof(RTL_PROCESS_MODULE_INFORMATION));

	PRTL_PROCESS_MODULES SystemModules;
	unsigned long InformationDumpSize;
	char* AsciiVersion;

	AsciiVersion = (char*)VirtualAlloc(0, wcslen(SystemModule) + 1, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (!AsciiVersion)
		return GENERAL_ERROR_ASSEMBLE(GENERAL_ERROR_HEADER_UM_UTILITIES, NTSTATUS_FROM_WIN32(GetLastError()));

	wcstombs(AsciiVersion, SystemModule, wcslen(SystemModule) + 1);

	NtQuerySystemInformation((SYSTEM_INFORMATION_CLASS)11, 0, 0, &InformationDumpSize);
	SystemModules = (PRTL_PROCESS_MODULES)VirtualAlloc(0, InformationDumpSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (!SystemModules)
	{
		VirtualFree(AsciiVersion, 0, MEM_RELEASE);
		return GENERAL_ERROR_ASSEMBLE(GENERAL_ERROR_HEADER_UM_UTILITIES, NTSTATUS_FROM_WIN32(GetLastError()));
	}

	NtQuerySystemInformation((SYSTEM_INFORMATION_CLASS)11, SystemModules, InformationDumpSize, &InformationDumpSize);

	for (unsigned long i = 0; i < SystemModules->NumberOfModules; i++)
	{
		if (!_stricmp((char*)SystemModules->Modules[i].FullPathName + SystemModules->Modules[i].OffsetToFileName, AsciiVersion))
		{
			memcpy(ModuleInformation, &SystemModules->Modules[i], sizeof(SystemModules->Modules[i]));
			VirtualFree(AsciiVersion, 0, MEM_RELEASE);
			VirtualFree(SystemModules, 0, MEM_RELEASE);
			return TRUE;
		}
	}

	VirtualFree(AsciiVersion, 0, MEM_RELEASE);
	VirtualFree(SystemModules, 0, MEM_RELEASE);
	return GENERAL_ERROR_ASSEMBLE(GENERAL_ERROR_HEADER_UM_UTILITIES, STATUS_NOT_FOUND) | 1;
}

static GeneralErrorCast FindHandleInfoByHandleAndPID(HANDLE Handle, unsigned long ProcessID, SYSTEM_HANDLE_TABLE_ENTRY_INFO* HandleInformation)
{
	if (Handle == INVALID_HANDLE_VALUE)
		return GENERAL_ERROR_ASSEMBLE(GENERAL_ERROR_HEADER_UM_UTILITIES, STATUS_INVALID_PARAMETER_1) | 1;

	if (!HandleInformation)
		return GENERAL_ERROR_ASSEMBLE(GENERAL_ERROR_HEADER_UM_UTILITIES, STATUS_INVALID_PARAMETER_3) | 1;

	memset(HandleInformation, 0, sizeof(SYSTEM_HANDLE_TABLE_ENTRY_INFO));

	PSYSTEM_HANDLE_INFORMATION HandleObjects;
	unsigned long InformationDumpSize;

	HandleObjects = (PSYSTEM_HANDLE_INFORMATION)VirtualAlloc(0, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (!HandleObjects)
		return GENERAL_ERROR_ASSEMBLE(GENERAL_ERROR_HEADER_UM_UTILITIES, NTSTATUS_FROM_WIN32(GetLastError()));

	NtQuerySystemInformation((SYSTEM_INFORMATION_CLASS)0x10, HandleObjects, 0x1000, &InformationDumpSize);
	VirtualFree(HandleObjects, 0, MEM_RELEASE);
	HandleObjects = (PSYSTEM_HANDLE_INFORMATION)VirtualAlloc(0, InformationDumpSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (!HandleObjects)
		return GENERAL_ERROR_ASSEMBLE(GENERAL_ERROR_HEADER_UM_UTILITIES, NTSTATUS_FROM_WIN32(GetLastError()));

	NtQuerySystemInformation((SYSTEM_INFORMATION_CLASS)0x10, HandleObjects, InformationDumpSize, &InformationDumpSize);

	for (unsigned long i = 0; i < HandleObjects->NumberOfHandles; i++)
	{
		if ((HandleObjects->Handles[i].UniqueProcessId == ProcessID) && (HandleObjects->Handles[i].HandleValue == (USHORT)Handle))
		{
			memcpy(HandleInformation, &HandleObjects->Handles[i], sizeof(HandleObjects->Handles[i]));
			VirtualFree(HandleObjects, 0, MEM_RELEASE);
			return TRUE;
		}
	}

	VirtualFree(HandleObjects, 0, MEM_RELEASE);
	return GENERAL_ERROR_ASSEMBLE(GENERAL_ERROR_HEADER_UM_UTILITIES, STATUS_NOT_FOUND) | 1;
}

static GeneralErrorCast GenerateSimpleModuleQuery(HANDLE ProcessHandle, SimpleLenghtQuery* Query, unsigned long long QuerySize, unsigned long long* RequiredSize)
{
	if ((!Query || !QuerySize) && (!RequiredSize))
		return GENERAL_ERROR_ASSEMBLE(GENERAL_ERROR_HEADER_UM_UTILITIES, STATUS_INVALID_PARAMETER) | 1;

	if (!Query || !QuerySize)
	{
		QuerySize = 0;
		Query = 0;
	}

	if (RequiredSize)
		(*RequiredSize) = 0;

	unsigned long ReqSize;
	MODULEINFO ModuleInfo;
	HMODULE * QueryRecast;

	if (RequiredSize)
	{
		if (!EnumProcessModules(ProcessHandle, ((HMODULE*)Query), ((QuerySize / sizeof(SimpleLenghtQuery)) * sizeof(HMODULE)), ((unsigned long*)RequiredSize)))
			return GENERAL_ERROR_ASSEMBLE(GENERAL_ERROR_HEADER_UM_UTILITIES, NTSTATUS_FROM_WIN32(GetLastError())) | 1;

		(*RequiredSize) = (((*RequiredSize) / sizeof(HMODULE)) * sizeof(SimpleLenghtQuery));
	}
	else
	{
		if (!EnumProcessModules(ProcessHandle, ((HMODULE*)Query), ((QuerySize / sizeof(SimpleLenghtQuery)) * sizeof(HMODULE)), &ReqSize))
			return GENERAL_ERROR_ASSEMBLE(GENERAL_ERROR_HEADER_UM_UTILITIES, NTSTATUS_FROM_WIN32(GetLastError())) | 1;
	}

	if (Query)
	{
		QueryRecast = ((HMODULE*)Query);

		for (unsigned long long i = ((QuerySize / sizeof(SimpleLenghtQuery)) - 1);; i--)
		{
			if (!GetModuleInformation(ProcessHandle, QueryRecast[i], &ModuleInfo, sizeof(ModuleInfo)))
				return GENERAL_ERROR_ASSEMBLE(GENERAL_ERROR_HEADER_UM_UTILITIES, NTSTATUS_FROM_WIN32(GetLastError())) | 1;

			Query[i].Size = ModuleInfo.SizeOfImage;
			Query[i].StartAddress = QueryRecast[i];

			if (!i)
				break;
		}
	}

	return STATUS_SUCCESS;
}

#endif
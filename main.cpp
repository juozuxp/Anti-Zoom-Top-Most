#include "Imports.h"
#include "Utilities.h"
#include "PEDisector.h"

#define DWORDPTR(dword) ((dword) & 0xFF), (((dword) >> 8) & 0xFF), (((dword) >> 16) & 0xFF), (((dword) >> 24) & 0xFF)

typedef struct _MappedImportDescriptor32
{
	unsigned long* OriginalFirstThunk;
	unsigned long* FirstThunk;
	IMAGE_IMPORT_DESCRIPTOR* ImportDescriptor;
} MappedImportDescriptor32, * PMappedImportDescriptor32;

GeneralErrorCast FindImport32(void* PEBuffer, const char* ImportName, MappedImportDescriptor32* ImportDesc)
{
	if (!PEBuffer)
		return GENERAL_ERROR_ASSEMBLE(GENERAL_ERROR_HEADER_PEDISECTOR, STATUS_INVALID_PARAMETER_1) | 1;
	if (!ImportName)
		return GENERAL_ERROR_ASSEMBLE(GENERAL_ERROR_HEADER_PEDISECTOR, STATUS_INVALID_PARAMETER_2) | 1;
	if (!ImportDesc)
		return GENERAL_ERROR_ASSEMBLE(GENERAL_ERROR_HEADER_PEDISECTOR, STATUS_INVALID_PARAMETER_3) | 1;

	memset(ImportDesc, 0, sizeof(MappedImportDescriptor));

	IMAGE_DOS_HEADER* DosHeader;
	IMAGE_NT_HEADERS32* NTHeaders;
	IMAGE_OPTIONAL_HEADER32* OptionalHeader;
	IMAGE_IMPORT_DESCRIPTOR* ImportDescriptor;

	DosHeader = (IMAGE_DOS_HEADER*)PEBuffer;
	NTHeaders = (IMAGE_NT_HEADERS32*)((char*)PEBuffer + DosHeader->e_lfanew);
	OptionalHeader = &NTHeaders->OptionalHeader;

	if (!OptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size)
		return GENERAL_ERROR_ASSEMBLE(GENERAL_ERROR_HEADER_PEDISECTOR, STATUS_MAPPED_FILE_SIZE_ZERO) | 1;

	ImportDescriptor = (IMAGE_IMPORT_DESCRIPTOR*)((char*)PEBuffer + OptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
	while (ImportDescriptor->Name)
	{
		unsigned long* OriginalFirstThunk = (unsigned long*)((char*)PEBuffer + ImportDescriptor->OriginalFirstThunk);
		unsigned long* FirstThunk = (unsigned long*)((char*)PEBuffer + ImportDescriptor->FirstThunk);

		if (!OriginalFirstThunk)
			OriginalFirstThunk = FirstThunk;

		for (; *OriginalFirstThunk; OriginalFirstThunk++, FirstThunk++)
		{
			if (!IMAGE_SNAP_BY_ORDINAL((unsigned long long) * OriginalFirstThunk))
			{
				IMAGE_IMPORT_BY_NAME* ImportByName = (IMAGE_IMPORT_BY_NAME*)((char*)PEBuffer + (unsigned long long) * OriginalFirstThunk);
				if (!_stricmp(ImportByName->Name, ImportName))
				{
					ImportDesc->OriginalFirstThunk = OriginalFirstThunk;
					ImportDesc->FirstThunk = FirstThunk;
					ImportDesc->ImportDescriptor = ImportDescriptor;
					return STATUS_SUCCESS;
				}
			}
		}
		ImportDescriptor++;
	}
	return GENERAL_ERROR_ASSEMBLE(GENERAL_ERROR_HEADER_PEDISECTOR, STATUS_NOT_FOUND) | 1;
}

int main()
{
	HWND ZPToolTip;
	MODULEENTRY32 USER32;
	HANDLE ProcessHandle;
	IMAGE_SECTION_HEADER* TextSection;
	MappedImportDescriptor32 NtSetWindowPos;

	void* ShellLocation;
	void* User32Dump;
	unsigned long ProcessID;

	ZPToolTip = FindWindowW(0, L"ZPToolBarParentWnd");
	GetWindowThreadProcessId(ZPToolTip, &ProcessID);
	ProcessHandle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, ProcessID);

	FindProcessModuleByNameA(ProcessID, "User32.dll", &USER32);

	User32Dump = VirtualAlloc(0, USER32.modBaseSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	
	ReadProcessMemory(ProcessHandle, USER32.hModule, User32Dump, USER32.modBaseSize, 0);

	FindImport32(User32Dump, "NtUserSetWindowPos", &NtSetWindowPos);
	FindSectionByName(User32Dump, ".text", &TextSection);

	ShellLocation = (((char*)USER32.hModule) + TextSection->VirtualAddress + TextSection->Misc.VirtualSize);
	unsigned char Shell[] =
	{
		0x81, 0x7c, 0x24, 0x04, DWORDPTR(((unsigned long long)ZPToolTip)),
		0x75, 0x08,
		0xC7, 0x44, 0x24, 0x8, DWORDPTR(0),
		0xE9, DWORDPTR(((char*)*NtSetWindowPos.FirstThunk) - ((char*)ShellLocation) - 0x17),
	};

	VirtualProtectEx(ProcessHandle, ShellLocation, sizeof(Shell), PAGE_EXECUTE_READWRITE, &ProcessID);
	WriteProcessMemory(ProcessHandle, ShellLocation, Shell, sizeof(Shell), 0);
	VirtualProtectEx(ProcessHandle, ShellLocation, sizeof(Shell), ProcessID, &ProcessID);

	unsigned long Hijacked = ((unsigned long)ShellLocation);
	
	VirtualProtectEx(ProcessHandle, ((char*)USER32.hModule) + (((char*)NtSetWindowPos.FirstThunk) - ((char*)User32Dump)), sizeof(Hijacked), PAGE_READWRITE, &ProcessID);
	WriteProcessMemory(ProcessHandle, ((char*)USER32.hModule) + (((char*)NtSetWindowPos.FirstThunk) - ((char*)User32Dump)), &Hijacked, sizeof(Hijacked), 0);
	VirtualProtectEx(ProcessHandle, ((char*)USER32.hModule) + (((char*)NtSetWindowPos.FirstThunk) - ((char*)User32Dump)), sizeof(Hijacked), ProcessID, &ProcessID);
}
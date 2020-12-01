#pragma once
#ifndef UM_Imports_HEADER_INCLUDED
#define UM_Imports_HEADER_INCLUDED

#pragma comment(lib, "ntdll.lib")

#include <Windows.h>
#include <psapi.h>
#include <winternl.h>
#include <ntstatus.h>
#ifdef UNICODE
#undef UNICODE
#include <TlHelp32.h>
#define UNICODE
#else
#include <TlHelp32.h>
#endif
#define _USE_MATH_DEFINES
#include <math.h>
#include <stdlib.h>
#include "GeneralStructures.h"
#include "GeneralErrors.h"

#pragma warning(disable:4996)

#define SeCreateTokenPrivilege 2
#define SeAssignPrimaryTokenPrivilege 3
#define SeLockMemoryPrivilege 4
#define SeIncreaseQuotaPrivilege 5
#define SeUnsolicitedInputPrivilege 0
#define SeMachineAccountPrivilege 6
#define SeTcbPrivilege 7
#define SeSecurityPrivilege 8
#define SeTakeOwnershipPrivilege 9
#define SeLoadDriverPrivilege 10
#define SeSystemProfilePrivilege 11
#define SeSystemtimePrivilege 12
#define SeProfileSingleProcessPrivilege 13
#define SeIncreaseBasePriorityPrivilege 14
#define SeCreatePagefilePrivilege 15
#define SeCreatePermanentPrivilege 16
#define SeBackupPrivilege 17
#define SeRestorePrivilege 18
#define SeShutdownPrivilege 19
#define SeDebugPrivilege 20
#define SeAuditPrivilege 21
#define SeSystemEnvironmentPrivilege 22
#define SeChangeNotifyPrivilege 23
#define SeRemoteShutdownPrivilege 24
#define SeUndockPrivilege 25
#define SeSyncAgentPrivilege 26
#define SeEnableDelegationPrivilege 27
#define SeManageVolumePrivilege 28
#define SeImpersonatePrivilege 29
#define SeCreateGlobalPrivilege 30
#define SeTrustedCredManAccessPrivilege 31
#define SeRelabelPrivilege 32
#define SeIncreaseWorkingSetPrivilege 33
#define SeTimeZonePrivilege 34
#define SeCreateSymbolicLinkPrivilege 35

typedef struct _SeFlags
{
	unsigned long long SeNull : 2;
	unsigned long long CreateTokenPrivilege : 1; // 2 SeCreateTokenPrivilege
	unsigned long long AssignPrimaryTokenPrivilege : 1; // 3 SeAssignPrimaryTokenPrivilege
	unsigned long long LockMemoryPrivilege : 1; // 4 SeLockMemoryPrivilege
	unsigned long long IncreaseQuotaPrivilege : 1; // 5 SeIncreaseQuotaPrivilege
	unsigned long long MachineAccountPrivilege : 1; // 6 SeMachineAccountPrivilege
	unsigned long long TcbPrivilege : 1; // 7 SeTcbPrivilege
	unsigned long long SecurityPrivilege : 1; // 8 SeSecurityPrivilege
	unsigned long long TakeOwnershipPrivilege : 1; // 9 SeTakeOwnershipPrivilege
	unsigned long long LoadDriverPrivilege : 1; // 10 SeLoadDriverPrivilege
	unsigned long long SystemProfilePrivilege : 1; // 11 SeSystemProfilePrivilege
	unsigned long long SystemtimePrivilege : 1; // 12 SeSystemtimePrivilege
	unsigned long long ProfileSingleProcessPrivilege : 1; // 13 SeProfileSingleProcessPrivilege
	unsigned long long IncreaseBasePriorityPrivilege : 1; // 14 SeIncreaseBasePriorityPrivilege
	unsigned long long CreatePagefilePrivilege : 1; // 15 SeCreatePagefilePrivilege
	unsigned long long CreatePermanentPrivilege : 1; // 16 SeCreatePermanentPrivilege
	unsigned long long BackupPrivilege : 1; // 17 SeBackupPrivilege
	unsigned long long RestorePrivilege : 1; // 18 SeRestorePrivilege
	unsigned long long ShutdownPrivilege : 1; // 19 SeShutdownPrivilege
	unsigned long long DebugPrivilege : 1; // 20 SeDebugPrivilege
	unsigned long long AuditPrivilege : 1; // 21 SeAuditPrivilege
	unsigned long long SystemEnvironmentPrivilege : 1; // 22 SeSystemEnvironmentPrivilege
	unsigned long long ChangeNotifyPrivilege : 1; // 23 SeChangeNotifyPrivilege
	unsigned long long RemoteShutdownPrivilege : 1; // 24 SeRemoteShutdownPrivilege
	unsigned long long UndockPrivilege : 1; // 25 SeUndockPrivilege
	unsigned long long SyncAgentPrivilege : 1; // 26 SeSyncAgentPrivilege
	unsigned long long EnableDelegationPrivilege : 1; // 27 SeEnableDelegationPrivilege
	unsigned long long ManageVolumePrivilege : 1; // 28 SeManageVolumePrivilege
	unsigned long long ImpersonatePrivilege : 1; // 29 SeImpersonatePrivilege
	unsigned long long CreateGlobalPrivilege : 1; // 30 SeCreateGlobalPrivilege
	unsigned long long TrustedCredManAccessPrivilege : 1; // 31 SeTrustedCredManAccessPrivilege
	unsigned long long RelabelPrivilege : 1; // 32 SeRelabelPrivilege
	unsigned long long IncreaseWorkingSetPrivilege : 1; // 33 SeIncreaseWorkingSetPrivilege
	unsigned long long TimeZonePrivilege : 1; // 34 SeTimeZonePrivilege
	unsigned long long CreateSymbolicLinkPrivilege : 1; // 35 SeCreateSymbolicLinkPrivilege
} SeFlags, * PSeFlags;

typedef struct _SEP_TOKEN_PRIVILEGES
{
	SeFlags Present;
	SeFlags Enabled;
	SeFlags EnabledByDefault;
} SEP_TOKEN_PRIVILEGES, * PSEP_TOKEN_PRIVILEGES;

typedef struct _SmallToken
{
	TOKEN_SOURCE TokenSource;
	LUID TokenID;
	LUID AuthenticationID;
	LUID ParentTokenID;
	LARGE_INTEGER ExperationTime;
	void * TokenLock;
	LUID ModifiedID;
	SEP_TOKEN_PRIVILEGES Priviliges;
} SmallToken, * PSmallToken;

typedef enum _THREAD_INFORMATION_CLASS_ALTERNATIVE 
{
	ThreadBasicInformation,
	ThreadTimes,
	ThreadPriority,
	ThreadBasePriority,
	ThreadAffinityMask,
	ThreadImpersonationToken,
	ThreadDescriptorTableEntry,
	ThreadEnableAlignmentFaultFixup,
	ThreadEventPair,
	ThreadQuerySetWin32StartAddress,
	ThreadZeroTlsCell,
	ThreadPerformanceCount,
	ThreadAmILastThread,
	ThreadIdealProcessor,
	ThreadPriorityBoost,
	ThreadSetTlsArrayAddress,
	// ThreadIsIoPending,
	ThreadHideFromDebugger = 17
} THREAD_INFORMATION_CLASS_ALTERNATIVE, * PTHREAD_INFORMATION_CLASS_ALTERNATIVE;

#define IRP_MJ_MAXIMUM_FUNCTION 0x1b

extern "C"
NTSYSAPI
NTSTATUS
NTAPI
NtCreateSection
(
	OUT PHANDLE SectionHandle,
	IN ULONG DesiredAccess,
	IN OPTIONAL POBJECT_ATTRIBUTES ObjectAttributes,
	IN OPTIONAL PLARGE_INTEGER MaximumSize,
	IN ULONG PageAttributess,
	IN ULONG SectionAttributes,
	IN OPTIONAL HANDLE FileHandle
);

extern "C"
NTSYSAPI
NTSTATUS
NTAPI
NtMapViewOfSection
(
	IN HANDLE SectionHandle,
	IN HANDLE ProcessHandle,
	IN OUT OPTIONAL PVOID * BaseAddress,
	IN OPTIONAL ULONG ZeroBits,
	IN SIZE_T CommitSize,
	IN OUT OPTIONAL PLARGE_INTEGER SectionOffset,
	IN OUT PSIZE_T ViewSize,
	IN ULONG InheritDisposition,
	IN OPTIONAL ULONG AllocationType,
	IN ULONG Protect
);

extern "C"
NTSYSAPI
NTSTATUS
NTAPI
NtOpenSection
(
	OUT PHANDLE SectionHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes
);

extern "C"
NTSYSAPI
LONG
RtlCompareUnicodeString
(
	PCUNICODE_STRING String1,
	PCUNICODE_STRING String2,
	BOOLEAN CaseInSensitive
);


extern "C"
NTSYSAPI
NTSTATUS
RtlAdjustPrivilege
(
	ULONG Privilege,
	BOOLEAN Enable,
	BOOLEAN CurrentThread,
	PBOOLEAN Enabled
);

extern "C"
NTSYSAPI
NTSTATUS
NTAPI
NtLoadDriver
(
	IN PUNICODE_STRING DriverServiceName
);

extern "C"
NTSYSAPI
NTSTATUS
NTAPI
NtUnloadDriver
(
	IN PUNICODE_STRING DriverServiceName
);

extern "C"
NTSYSAPI
NTSTATUS
NTAPI
NtQueryDirectoryObject
(
	IN HANDLE DirectoryHandle,
	IN OPTIONAL PVOID Buffer,
	IN ULONG Length,
	IN BOOLEAN ReturnSingleEntry,
	IN BOOLEAN RestartScan,
	IN OUT PULONG  Context,
	OUT OPTIONAL PULONG  ReturnLength
);

extern "C"
NTSYSAPI
NTSTATUS
NTAPI
NtOpenDirectoryObject
(
	OUT PHANDLE DirectoryHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes
);

extern "C"
NTSYSAPI
NTSTATUS
NTAPI
NtTerminateProcess
(
	HANDLE ProcessHandle,
	NTSTATUS ExitStatus
);

extern "C"
NTSYSAPI
NTSTATUS
NTAPI
NtSuspendProcess
(
	HANDLE ProcessHandle
);

extern "C"
NTSYSAPI
NTSTATUS
NTAPI
NtResumeProcess
(
	HANDLE ProcessHandle
);

extern "C"
NTSYSAPI
NTSTATUS
NTAPI
NtOpenSymbolicLinkObject
(
	OUT PHANDLE LinkHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes
);

extern "C"
NTSYSAPI
NTSTATUS
NTAPI
NtQuerySymbolicLinkObject
(
	IN HANDLE LinkHandle,
	IN OUT PUNICODE_STRING LinkTarget,
	OUT OPTIONAL PULONG ReturnedLength
);

typedef struct _ModuleEntry
{
	void* ModuleBase;
	unsigned long ModuleSize;
	char ModuleName[MAX_PATH];
	char ModulePath[MAX_PATH];
} ModuleEntry, * PModuleEntry;

typedef struct _SYSTEM_HANDLE_TABLE_ENTRY_INFO
{
	USHORT UniqueProcessId;
	USHORT CreatorBackTraceIndex;
	UCHAR ObjectTypeIndex;
	UCHAR HandleAttributes;
	USHORT HandleValue;
	PVOID Object;
	ULONG GrantedAccess;
} SYSTEM_HANDLE_TABLE_ENTRY_INFO, * PSYSTEM_HANDLE_TABLE_ENTRY_INFO;

typedef struct _SYSTEM_HANDLE_INFORMATION
{
	ULONG NumberOfHandles;
	SYSTEM_HANDLE_TABLE_ENTRY_INFO Handles[1];
} SYSTEM_HANDLE_INFORMATION, * PSYSTEM_HANDLE_INFORMATION;

typedef struct _RTL_PROCESS_MODULE_INFORMATION
{
	HANDLE Section;
	PVOID MappedBase;
	PVOID ImageBase;
	ULONG ImageSize;
	ULONG Flags;
	USHORT LoadOrderIndex;
	USHORT InitOrderIndex;
	USHORT LoadCount;
	USHORT OffsetToFileName;
	UCHAR FullPathName[256];
} RTL_PROCESS_MODULE_INFORMATION, * PRTL_PROCESS_MODULE_INFORMATION;

typedef struct _RTL_PROCESS_MODULES
{
	ULONG NumberOfModules;
	RTL_PROCESS_MODULE_INFORMATION Modules[1];
} RTL_PROCESS_MODULES, * PRTL_PROCESS_MODULES;

typedef struct _DISPATCHER_HEADER
{
	union
	{
		struct
		{
			UCHAR Type;
			union
			{
				UCHAR Abandoned;
				UCHAR Absolute;
				UCHAR NpxIrql;
				UCHAR Signalling;
			};
			union
			{
				UCHAR Size;
				UCHAR Hand;
			};
			union
			{
				UCHAR Inserted;
				UCHAR DebugActive;
				UCHAR DpcActive;
			};
		};
		LONG Lock;
	};
	LONG SignalState;
	LIST_ENTRY WaitListHead;
} DISPATCHER_HEADER, * PDISPATCHER_HEADER;

typedef struct _KEVENT
{
	DISPATCHER_HEADER Header;
} KEVENT, * PKEVENT;

typedef struct _KDEVICE_QUEUE
{
	SHORT Type;
	SHORT Size;
	LIST_ENTRY DeviceListHead;
	ULONG Lock;
	UCHAR Busy;
} KDEVICE_QUEUE, * PKDEVICE_QUEUE;

typedef struct _KDPC
{
	UCHAR Type;
	UCHAR Importance;
	WORD Number;
	LIST_ENTRY DpcListEntry;
	PVOID DeferredRoutine;
	PVOID DeferredContext;
	PVOID SystemArgument1;
	PVOID SystemArgument2;
	PVOID DpcData;
} KDPC, * PKDPC;

typedef struct _FILE_OBJECT {
	short Type;
	short Size;
	void * DeviceObject;
	void * Vpb;
	void * FsContext;
	void * FsContext2;
	void * SectionObjectPointer;
	void * PrivateCacheMap;
	NTSTATUS FinalStatus;
	void * RelatedFileObject;
	BOOLEAN LockOperation;
	BOOLEAN DeletePending;
	BOOLEAN ReadAccess;
	BOOLEAN WriteAccess;
	BOOLEAN DeleteAccess;
	BOOLEAN SharedRead;
	BOOLEAN SharedWrite;
	BOOLEAN SharedDelete;
	unsigned long Flags;
	UNICODE_STRING FileName;
	LARGE_INTEGER CurrentByteOffset;
	__volatile unsigned long Waiters;
	__volatile unsigned long Busy;
	void* LastLock;
	KEVENT Lock;
	KEVENT Event;
	__volatile void * CompletionContext;
	KSPIN_LOCK IrpListLock;
	LIST_ENTRY IrpList;
	__volatile void * FileObjectExtension;
} FILE_OBJECT, * PFILE_OBJECT;

typedef struct _DEVICE_OBJECT {
	short Type;
	USHORT Size;
	LONG ReferenceCount;
	void * DriverObject;
	void * NextDevice;
	void * AttachedDevice;
	void * CurrentIrp;
	void * Timer;
	ULONG Flags;
	ULONG Characteristics;
	__volatile void * Vpb;
	PVOID DeviceExtension;
	DEVICE_TYPE DeviceType;
	CCHAR StackSize;
	LIST_ENTRY ListEntry;
	ULONG AlignmentRequirement;
	KDEVICE_QUEUE DeviceQueue;
	KDPC Dpc;
	ULONG ActiveThreadCount;
	void * SecurityDescriptor;
	KEVENT DeviceLock;
	USHORT SectorSize;
	USHORT Spare1;
	void * DeviceObjectExtension;
	PVOID Reserved;
} DEVICE_OBJECT, * PDEVICE_OBJECT;

typedef struct _DRIVER_OBJECT {
	short Type;
	short Size;
	void * DeviceObject;
	ULONG Flags;
	PVOID DriverStart;
	ULONG DriverSize;
	PVOID DriverSection;
	void * DriverExtension;
	UNICODE_STRING DriverName;
	void * HardwareDatabase;
	void * FastIoDispatch;
	void * DriverInit;
	void * DriverStartIo;
	void * DriverUnload;
	void * MajorFunction[IRP_MJ_MAXIMUM_FUNCTION + 1];
} DRIVER_OBJECT, * PDRIVER_OBJECT;

typedef struct _VULNERABLE_DRIVER_EXECUTE
{
	void* Function;
	void** FunctionReturn;
	BOOLEAN UMExecute;
	unsigned long ArgumentCount;
	void* Arguments[4];
} VULNERABLE_DRIVER_EXECUTE, * PVULNERABLE_DRIVER_EXECUTE;

typedef struct _LDR_DATA_TABLE_ENTRY_ALTERNATIVE
{
	LIST_ENTRY InLoadOrderLinks;
	LIST_ENTRY InMemoryOrderLinks;
	union
	{
		LIST_ENTRY InInitializationOrderLinks;
		LIST_ENTRY InProgressLinks;
	};
	PVOID           DllBase;
	PVOID           Entrypoint;
	ULONG           SizeOfImage;
	UNICODE_STRING  FullDllName;
	UNICODE_STRING  BaseDllName;
} LDR_DATA_TABLE_ENTRY_ALTERNATIVE, * PLDR_DATA_TABLE_ENTRY_ALTERNATIVE;

typedef struct _PEB_LDR_DATA_ALTERNATIVE
{
	ULONG       Length;
	UCHAR       Initialized;
	PVOID       SsHandle;
	LIST_ENTRY  InLoadOrderModuleList;
	LIST_ENTRY  InMemoryOrderModuleList;
	LIST_ENTRY  InInitializationOrderModuleList;
} PEB_LDR_DATA_ALTERNATIVE, * PPEB_LDR_DATA_ALTERNATIVE;

typedef struct _PEB_ALTERNATIVE
{
	BOOLEAN                         InheritedAddressSpace;
	BOOLEAN                         ReadImageFileExecOptions;
	BOOLEAN                         BeingDebugged;
	BOOLEAN                         BitField;
	HANDLE                          Mutant;
	PVOID                           ImageBaseAddress;
	PPEB_LDR_DATA_ALTERNATIVE       Ldr;
	PRTL_USER_PROCESS_PARAMETERS    ProcessParameters;
	PVOID                           SubSystemData;
	PVOID                           ProcessHeap;
	PVOID                           FastPebLock;
} PEB_ALTERNATIVE, *PPEB_ALTERNATIVE;

typedef struct _OBJECT_DIRECTORY_INFORMATION 
{
	UNICODE_STRING Name;
	UNICODE_STRING TypeName;
} OBJECT_DIRECTORY_INFORMATION, * POBJECT_DIRECTORY_INFORMATION;

typedef struct _THREAD_BASIC_INFORMATION 
{
	NTSTATUS                ExitStatus;
	PVOID                   TebBaseAddress;
	CLIENT_ID               ClientId;
	KAFFINITY               AffinityMask;
	KPRIORITY               Priority;
	KPRIORITY               BasePriority;
} THREAD_BASIC_INFORMATION, * PTHREAD_BASIC_INFORMATION;

#endif
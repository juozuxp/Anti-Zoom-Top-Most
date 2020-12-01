#pragma once
#ifndef BOTH_GeneralErrors_HEADER_INCLUDED
#define BOTH_GeneralErrors_HEADER_INCLUDED

#define GENERAL_ERROR_HEADER_STRUCTUREDLISTS 0x0
#define GENERAL_ERROR_HEADER_PHYSICALMEMORY 0x1
#define GENERAL_ERROR_HEADER_PEMAPPER 0x2
#define GENERAL_ERROR_HEADER_PEDISECTOR 0x3
#define GENERAL_ERROR_HEADER_MEMORYEXPLORER 0x4
#define GENERAL_ERROR_HEADER_BUFFERPARSER 0x5
#define GENERAL_ERROR_HEADER_KM_OBJECTQUERY 0x6
#define GENERAL_ERROR_HEADER_KM_UTILITIES 0x7
#define GENERAL_ERROR_HEADER_UM_UTILITIES 0x8
#define GENERAL_ERROR_HEADER_UM_MANUALLOADLIBRARY 0x9
#define GENERAL_ERROR_HEADER_UM_DRIVERMAPPER 0xA
#define GENERAL_ERROR_HEADER_UM_CONSOLESWITCHES 0xB
#define GENERAL_ERROR_HEADER_UM_VULNERABLE_CPUZ 0xC
#define GENERAL_ERROR_HEADER_UM_VULNERABLE_GIGABYTE 0xD
#define GENERAL_ERROR_HEADER_UM_VULNERABLE_GMEREK 0xE
#define GENERAL_ERROR_HEADER_UM_VULNERABLE_INTEL 0xF
#define GENERAL_ERROR_HEADER_KM_PHYSICALMAPPER 0x10
#define GENERAL_ERROR_HEADER_BASICUTILITIES 0x11

#define GENERAL_ERROR_ASSEMBLE(FileIndex, NTStatus) (((((unsigned long long)(NTStatus)) & ((1ull << 32) - 1)) << 32) | ((((unsigned long long)(__LINE__)) & ((1ull << 21) - 1)) << 11) | ((((unsigned long long)(FileIndex)) & ((1ull << 10) - 1)) << 1))

#define GENERAL_ERROR_NTSTATUS(GeneralError) (((GeneralError) >> 32) & ((1 << 32) - 1))

typedef union _GeneralError
{
	unsigned long long ErrorValue;
	struct
	{
		unsigned long long GeneralHeader : 1;
		unsigned long long FileIndex : 10;
		unsigned long long ErroredLine : 21;
		unsigned long long NTStatus : 32;
	};
} GeneralError, *PGeneralError;

typedef unsigned long long _GeneralErrorCast, GeneralErrorCast, *PGeneralErrorCast;

#endif
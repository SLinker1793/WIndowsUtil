#include "pch.h"

#include <Windows.h>

#include "ProcessHelper.h"

#include <Psapi.h>
#include <stdlib.h>
#include <strsafe.h>
#pragma comment (lib, "psapi.lib")

#ifndef RETURN
#define RETURN(var, val) {var = val;goto Exit;}
#endif

typedef enum _PROCESSINFOCLASS
{
    ProcessBasicInformation = 0,
	ProcessWow64Information = 26
} PROCESSINFOCLASS;

typedef struct
{
	PVOID       ExitStatus;
	PVOID       PebBaseAddress;
    PVOID       AffinityMast;
    PVOID       BasePriority;
	ULONG_PTR   UniqueProcessId;
	ULONG_PTR   InheritedFromUniqueProcessId;

}PROCESS_BASIC_INFORMATION;

typedef UINT (WINAPI* FN_ZwQueryInformationProcess)(
  _In_       HANDLE ProcessHandle,
  _In_       PROCESSINFOCLASS ProcessInformationClass,
  _Out_      PVOID ProcessInformation,
  _In_       ULONG ProcessInformationLength,
  _Out_opt_  PULONG ReturnLength
);

CProcessHelper::CProcessHelper(void)
{
}

CProcessHelper::~CProcessHelper(void)
{
}

BOOL CProcessHelper::GetProcessPathByPid(DWORD pid, PWSTR pProcessPath, SIZE_T size)
{
	BOOL success = FALSE;

    HANDLE process = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_READ, FALSE, pid);
    if (process == NULL)
    {
        return FALSE;
    }
	
    WCHAR orgProcessPath[MAX_PATH] = {0};
    RtlZeroMemory(orgProcessPath, sizeof(orgProcessPath));

    success = (BOOL)GetModuleFileNameExW(process, NULL, orgProcessPath, sizeof(orgProcessPath));
    if (success)
    {
        WCHAR longProcessPath[MAX_PATH] = {0};
        RtlZeroMemory(longProcessPath, sizeof(longProcessPath));
        
        GetLongPathName(orgProcessPath, longProcessPath, _countof(longProcessPath));
        StringCbCopyW(pProcessPath, size, longProcessPath);
    }

    if (process)
    {
        CloseHandle(process);
    }

	return success;
}

BOOL CProcessHelper::GetParentId(DWORD pid, DWORD* parentId)
{
	BOOL success = FALSE;

	LONG status;
	DWORD dwParentPID = 0;
	HANDLE hProcess = NULL;
	PROCESS_BASIC_INFORMATION pbi;
    HMODULE ntdll = NULL;

	do
	{
        ntdll = LoadLibrary(L"ntdll");
        if (ntdll == NULL)
        {
            break;
        }
		
		FN_ZwQueryInformationProcess pfnNtQueryInformationProcess = (FN_ZwQueryInformationProcess)GetProcAddress(
			ntdll,
			"NtQueryInformationProcess"
			);

		if (!pfnNtQueryInformationProcess)
		{
			break;
		}

        hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pid);
		if (!hProcess)
		{
			break;
		}

		status = pfnNtQueryInformationProcess( hProcess,
			ProcessBasicInformation,
			(PVOID)&pbi,
			sizeof(PROCESS_BASIC_INFORMATION),
			NULL
			);

		if  (!status)
		{
			dwParentPID = (DWORD)pbi.InheritedFromUniqueProcessId;
			success = TRUE;
		}

	} while (FALSE);
	
	if (hProcess)
    {
		CloseHandle(hProcess);
        hProcess = NULL;
    }

    if (ntdll != NULL)
    {
        FreeLibrary(ntdll);
        ntdll = NULL;
    }
	
	*parentId = dwParentPID;

	return success;
}

BOOL CProcessHelper::GetModuleNameByAddressWow64(DWORD pid, DWORD_PTR moduleAddress, PWSTR pModuleName, SIZE_T size)
{
    if (!IsWow64ModeProcess(pid))
    {
        return FALSE;
    }

    BOOL success = FALSE;
	HMODULE modules[1024] = {NULL};
    RtlZeroMemory(modules, sizeof(modules));
	DWORD need = 0;

    HANDLE process = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_READ, FALSE, pid);
    if (process == NULL)
    {
        return FALSE;
    }
    HMODULE psapi = LoadLibrary(L"psapi.dll");
    if (psapi)
    {
        typedef BOOL (WINAPI* FN_EnumProcessModulesEx)(HANDLE hProcess, HMODULE *lphModule, DWORD cb, LPDWORD lpcbNeeded, DWORD dwFilterFlag);
        FN_EnumProcessModulesEx pfnEnumProcessModulesEx = (FN_EnumProcessModulesEx)GetProcAddress(psapi, "EnumProcessModulesEx");
        if (pfnEnumProcessModulesEx)
        {
            if (!pfnEnumProcessModulesEx(process, modules, sizeof(modules), &need, LIST_MODULES_32BIT))
            {
				RETURN(success, FALSE);
			}
        }
		else
		{
			if (!SupplantEnumProcessModulesWow64(process, modules, sizeof(modules), &need))
			{
				RETURN(success, FALSE);
			}
		}

		int count = need / sizeof(HMODULE);
        for (int i = 0; i < count; ++i)
        {
            MODULEINFO modInfo = {0};
            if (GetModuleInformation(process, modules[i], &modInfo, sizeof(modInfo)))
            {
                DWORD_PTR startAddr = (DWORD_PTR)modInfo.lpBaseOfDll;
                DWORD_PTR endAddr = (DWORD_PTR)(startAddr + modInfo.SizeOfImage);
                if (moduleAddress >= startAddr && moduleAddress <= endAddr)
                {
                    GetModuleFileNameExW(process, modules[i], pModuleName, (DWORD)size);
                    RETURN(success, TRUE);
                }
            }
        }
    }
    
Exit:
	if (psapi)
	{
		FreeLibrary(psapi);
		psapi = NULL;
	}
    if (process)
    {
        CloseHandle(process);
    }

    return success;
}

BOOL CProcessHelper::GetModuleNameByAddress(DWORD pid, DWORD_PTR moduleAddress, PWSTR pModuleName, SIZE_T size)
{
	BOOL success = FALSE;
	HMODULE modules[1024] = {NULL};
    RtlZeroMemory(modules, sizeof(modules));
	DWORD need = 0;

    HANDLE process = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_READ, FALSE, pid);
    if (process == NULL)
    {
        return FALSE;
    }

    if (EnumProcessModules(process, modules, sizeof(modules), &need))
    {
        int count = need / sizeof(HMODULE);
        for (int i = 0; i < count; ++i)
        {
            MODULEINFO modInfo = {0};
            if (GetModuleInformation(process, modules[i], &modInfo, sizeof(modInfo)))
            {
                DWORD_PTR startAddr = (DWORD_PTR)modInfo.lpBaseOfDll;
                DWORD_PTR endAddr = (DWORD_PTR)(startAddr + modInfo.SizeOfImage);
                if (moduleAddress >= startAddr && moduleAddress <= endAddr)
                {
                    GetModuleFileNameExW(process, modules[i], pModuleName, (DWORD)size);
                    RETURN(success, TRUE);
                }
            }
        }
    }  

Exit:

    if (process)
    {
        CloseHandle(process);
    }

	return success;	
}

BOOL CProcessHelper::IsLoadedModuleWow64(DWORD pid, PWSTR pModulePath)
{
	if (!IsWow64ModeProcess(pid))
    {
        return FALSE;
    }

	BOOL success = FALSE;
	HMODULE modules[1024] = {NULL};
    RtlZeroMemory(modules, sizeof(modules));
	DWORD need = 0;

    HANDLE process = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_READ, FALSE, pid);
    if (process == NULL)
    {
        return FALSE;
    }

	HMODULE psapi = LoadLibrary(L"psapi.dll");
	if (psapi)
	{
		typedef BOOL (WINAPI* FN_EnumProcessModulesEx)(HANDLE hProcess, HMODULE *lphModule, DWORD cb, LPDWORD lpcbNeeded, DWORD dwFilterFlag);
        FN_EnumProcessModulesEx pfnEnumProcessModulesEx = (FN_EnumProcessModulesEx)GetProcAddress(psapi, "EnumProcessModulesEx");
        if (pfnEnumProcessModulesEx)
        {
            if (!pfnEnumProcessModulesEx(process, modules, sizeof(modules), &need, LIST_MODULES_32BIT))
            {
				RETURN(success, FALSE);
			}
        }
		else
		{
			if (!SupplantEnumProcessModulesWow64(process, modules, sizeof(modules), &need))
			{
				RETURN(success, FALSE);
			}
		}

		WCHAR moduleName[MAX_PATH] = {0};

		int count = need / sizeof(HMODULE);
		for (int i = 0; i < count; ++i)
		{
			MODULEINFO modInfo = {0};
			if (GetModuleInformation(process, modules[i], &modInfo, sizeof(modInfo)))
			{
				RtlZeroMemory(moduleName, sizeof(moduleName));
				GetModuleFileNameExW(process, modules[i], moduleName, sizeof(moduleName));

				if (_wcsicmp(moduleName, pModulePath) == 0)
				{
					RETURN(success, TRUE);
				}
			}
		}
	}
Exit:

    if (process)
    {
        CloseHandle(process);
    }

	return success;
}

BOOL CProcessHelper::IsLoadedModule(DWORD pid, PWSTR pModulePath)
{
	BOOL success = FALSE;
	HMODULE modules[1024] = {NULL};
    RtlZeroMemory(modules, sizeof(modules));
	DWORD need = 0;

    HANDLE process = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_READ, FALSE, pid);
    if (process == NULL)
    {
        return FALSE;
    }
	
    WCHAR moduleName[MAX_PATH] = {0};
	if (EnumProcessModules(process, modules, sizeof(modules), &need))
	{
		int count = need / sizeof(HMODULE);
		for (int i = 0; i < count; ++i)
		{
			MODULEINFO modInfo = {0};
			if (GetModuleInformation(process, modules[i], &modInfo, sizeof(modInfo)))
			{
                RtlZeroMemory(moduleName, sizeof(moduleName));
                GetModuleFileNameExW(process, modules[i], moduleName, sizeof(moduleName));

				if (_wcsicmp(moduleName, pModulePath) == 0)
                {   
					RETURN(success, TRUE);
				}
			}
		}
	}

Exit:

    if (process)
    {
        CloseHandle(process);
    }

	return success;	
}

BOOL CProcessHelper::IsWow64ModeProcess(DWORD processId)
{
#ifndef _M_X64
    return FALSE;
#endif

    typedef BOOL (WINAPI* FN_IsWow64Process)(HANDLE, PBOOL);
    static FN_IsWow64Process pfnIsWow64Process = (FN_IsWow64Process)GetProcAddress(GetModuleHandle(L"kernel32"), "IsWow64Process");

    if (pfnIsWow64Process == NULL)
    {
        return FALSE;
    }

    BOOL wow64 = FALSE;

    HANDLE process = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_READ, FALSE, processId);
    if (process)
    {
        pfnIsWow64Process(process, &wow64);
        CloseHandle(process);
    }
    
    return wow64;
}

typedef struct _PEB_LDR_DATA
{
    ULONG       Length;
    ULONG       Initialized;
    PVOID       SsHandle;
    LIST_ENTRY  InLoadOrderModuleList;
    LIST_ENTRY  InMemoryOrderModuleList;
    LIST_ENTRY  InInitializationOrderModuleList;
} PEB_LDR_DATA, *PPEB_LDR_DATA;

typedef struct _UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR Buffer;
} UNICODE_STRING, *PUNICODE_STRING;

typedef struct _UNICODE_STRING32
{  
    USHORT  Length;
    USHORT  MaximumLength;
    ULONG32 Buffer;
} UNICODE_STRING32, *PUNICODE_STRING32; 

typedef struct _LDR_DATA_TABLE_ENTRY
{
    LIST_ENTRY      InLoadOrderModuleList;
    LIST_ENTRY      InMemoryOrderModuleList;
    LIST_ENTRY      InInitializationOrderModuleList;

    PVOID           BaseAddress;
    PVOID           EntryPoint;
    ULONG           SizeOfImage;
    UNICODE_STRING  FullDllName;
    UNICODE_STRING  BaseDllName;
    ULONG           Flags;
    SHORT           LoadCount;
    SHORT           TlsIndex;
    LIST_ENTRY      HashTableEntry;
    ULONG           TimeDateStamp;
} LDR_DATA_TABLE_ENTRY, *PLDR_DATA_TABLE_ENTRY;

typedef struct _RTL_USER_PROCESS_PARAMETERS
{
    BYTE Reserved1[16];
    PVOID Reserved2[10];
    UNICODE_STRING ImagePathName;
    UNICODE_STRING CommandLine;
} RTL_USER_PROCESS_PARAMETERS, *PRTL_USER_PROCESS_PARAMETERS;

typedef
VOID
(NTAPI *PPS_POST_PROCESS_INIT_ROUTINE) (
    VOID
    );

typedef struct _PEB {
    BYTE Reserved1[2];
    BYTE BeingDebugged;
    BYTE Reserved2[1];
    PVOID Reserved3;
	ULONG_PTR ImageBaseAddress;
    PPEB_LDR_DATA Ldr;
} PEB, *PPEB;

typedef struct _PEB_LDR_DATA32
{
    ULONG32       Length;
    ULONG32       Initialized;
    ULONG32       SsHandle;
    LIST_ENTRY32  InLoadOrderModuleList;
    LIST_ENTRY32  InMemoryOrderModuleList;
    LIST_ENTRY32  InInitializationOrderModuleList;
} PEB_LDR_DATA32, *PPEB_LDR_DATA32;

typedef struct _LDR_DATA_TABLE_ENTRY32
{
    LIST_ENTRY32    InLoadOrderModuleList;
    LIST_ENTRY32    InMemoryOrderModuleList;
    LIST_ENTRY32    InInitializationOrderModuleList;

    ULONG32         BaseAddress;
    ULONG32         EntryPoint;
    ULONG32         SizeOfImage;
    UNICODE_STRING32   FullDllName;
    UNICODE_STRING32   BaseDllName;
    ULONG32         Flags;
    SHORT           LoadCount;
    SHORT           TlsIndex;
    LIST_ENTRY32     HashTableEntry;
    ULONG32         TimeDateStamp;
} LDR_DATA_TABLE_ENTRY32, *PLDR_DATA_TABLE_ENTRY32;

typedef struct _RTL_USER_PROCESS_PARAMETERS32
{
    BYTE Reserved1[16];
    ULONG32 Reserved2[10];
    UNICODE_STRING ImagePathName;
    UNICODE_STRING CommandLine;
} RTL_USER_PROCESS_PARAMETERS32, *PRTL_USER_PROCESS_PARAMETERS32;

typedef struct _PEB32
{
    BYTE Reserved1[2];
    BYTE BeingDebugged;
    BYTE Reserved2[1];
    ULONG32 Reserved3;
	ULONG32 ImageBaseAddress;
    ULONG32 Ldr;
} PEB32, *PPEB32;

BOOL CProcessHelper::SupplantEnumProcessModulesWow64(HANDLE hProcess, HMODULE *lphModule, DWORD cb, LPDWORD lpcbNeeded)
{
	FN_ZwQueryInformationProcess pfnZwQueryInformationProcess = NULL;
	ULONG retLength;
	BOOL bRet = FALSE;

	HMODULE hNtdll = NULL;
	hNtdll = LoadLibrary(L"ntdll.dll");
	
	if (hNtdll)
	{
		*lpcbNeeded = 0;
		pfnZwQueryInformationProcess = (FN_ZwQueryInformationProcess)GetProcAddress(hNtdll, "ZwQueryInformationProcess");
		if (pfnZwQueryInformationProcess)
		{
			SIZE_T readSize = 0;
			ULONG_PTR readOffset = 0;
			ULONG_PTR fieldOffset = 0;
			LDR_DATA_TABLE_ENTRY32 ldrModule = {0};

			pfnZwQueryInformationProcess(hProcess, ProcessWow64Information, &readOffset, sizeof(ULONG_PTR), &retLength);

			fieldOffset = FIELD_OFFSET(PEB32, Ldr);	// peb32 ldr 위치

			readOffset = (ULONG_PTR)((PCHAR)readOffset + fieldOffset);	// PEB->Ldr 위치

			BOOL bResult = ReadProcessMemory(hProcess, (PVOID)readOffset, &readOffset, sizeof(ULONG32), &readSize);

			readOffset += FIELD_OFFSET(PEB_LDR_DATA32, InLoadOrderModuleList);	// PEB_LDR_DATA32->InLoadOrderModuleList 위치

			bResult = ReadProcessMemory(hProcess, (PVOID)readOffset, &readOffset, sizeof(ULONG32), &readSize);

			fieldOffset = FIELD_OFFSET(LDR_DATA_TABLE_ENTRY32, InLoadOrderModuleList);	// LDR_DATA_TABLE_ENTRY->InLoadOrderModuleList 위치 - 사실상 0 이며 다른 리스트를 위해 존재

			readOffset = readOffset - fieldOffset;

			WCHAR dllPath[MAX_PATH] = {L' ',};
			UINT maxModuleCount = cb / sizeof(lphModule[0]);

			for(UINT moduleCount = 0; moduleCount < maxModuleCount; moduleCount++)
			{
				ZeroMemory(&ldrModule, sizeof(LDR_DATA_TABLE_ENTRY32));
				ZeroMemory(dllPath, sizeof(dllPath));

				bResult = ReadProcessMemory(hProcess, (PVOID)(readOffset), &ldrModule, sizeof(LDR_DATA_TABLE_ENTRY32), &readSize);
				if (ldrModule.BaseAddress == NULL)
				{
					bRet = TRUE;
					break;
				}

				readOffset = (ULONG_PTR)ldrModule.FullDllName.Buffer;

				bResult = ReadProcessMemory(hProcess, (PVOID)readOffset, dllPath, ldrModule.FullDllName.Length, &readSize);

				lphModule[moduleCount] = (HMODULE)ldrModule.BaseAddress;;

				if (lphModule[moduleCount])
				{
					*lpcbNeeded += sizeof(HMODULE);
				}

				readOffset = (ULONG_PTR)((PCHAR)ldrModule.InLoadOrderModuleList.Flink - fieldOffset);	// 다음 리스트
			}
		}
		FreeLibrary(hNtdll);
		hNtdll = NULL;
	}

	return bRet;
}
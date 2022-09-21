#pragma once

class CProcessHelper
{
public:
    CProcessHelper(void);
    virtual ~CProcessHelper(void);

public:
    static BOOL         GetProcessPathByPid(DWORD pid, PWSTR pProcessPath, SIZE_T size);
    static BOOL         GetParentId(DWORD pid, DWORD* parentId);
    static BOOL         GetModuleNameByAddressWow64(DWORD pid, DWORD_PTR moduleAddress, PWSTR pModuleName, SIZE_T size);
    static BOOL         GetModuleNameByAddress(DWORD pid, DWORD_PTR moduleAddress, PWSTR pModuleName, SIZE_T size);
    static BOOL         IsLoadedModuleWow64(DWORD pid, PWSTR pModulePath);	
    static BOOL         IsLoadedModule(DWORD pid, PWSTR pModulePath);
    static BOOL         IsWow64ModeProcess(DWORD processId);
	static BOOL         SupplantEnumProcessModulesWow64(HANDLE hProcess, HMODULE *lphModule, DWORD cb, LPDWORD lpcbNeeded);
};


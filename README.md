# SLinkerProjects

Build Enviroment
* Visual Studio 2019
</br>

ProcessHelper Class
BOOL GetProcessPathByPid(DWORD pid, PWSTR pProcessPath, SIZE_T size);
* Get parent process id for target pid
BOOL GetParentId(DWORD pid, DWORD* parentId);
BOOL GetModuleNameByAddressWow64(DWORD pid, DWORD_PTR moduleAddress, PWSTR pModuleName, SIZE_T size);
BOOL GetModuleNameByAddress(DWORD pid, DWORD_PTR moduleAddress, PWSTR pModuleName, SIZE_T size);
BOOL IsLoadedModuleWow64(DWORD pid, PWSTR pModulePath);	
BOOL IsLoadedModule(DWORD pid, PWSTR pModulePath);
BOOL IsWow64ModeProcess(DWORD processId);
BOOL SupplantEnumProcessModulesWow64(HANDLE hProcess, HMODULE *lphModule, DWORD cb, LPDWORD lpcbNeeded);
BOOL ShellExecuteAs(BOOL bAdmin, LPCTSTR lpFile, LPCTSTR lpParameters = NULL, LPCTSTR lpDirectory = NULL, BOOL bHide = FALSE);



Supports

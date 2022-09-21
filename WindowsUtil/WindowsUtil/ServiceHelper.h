#pragma once

class CServiceHelper
{
public:
	CServiceHelper(PCWSTR pServiceName);	
	virtual ~CServiceHelper(void);

private:
	CServiceHelper(void);
	CServiceHelper(const CServiceHelper&);
	CServiceHelper& operator=(const CServiceHelper&);

public:
	BOOL	Create(PCWSTR pModulePath, BOOL driver, BOOL autuStart, BOOL start) const;
	BOOL	Delete(void) const;
	BOOL	Start(PCWSTR pParam1 = NULL, PCWSTR pParam2 = NULL, PCWSTR pParam3 = NULL) const;
	BOOL	Stop(DWORD timeOut = 2500) const;
	BOOL	SendControlCode(DWORD dwCtrlCode) const;
	BOOL	IsRunning(void) const;
    BOOL WaitStatus(DWORD waitForServiceStatus, DWORD timeOut = 2500) const;
	BOOL	IsExists(void) const;
	DWORD GetCurrentStatus(void) const;
	
	PCWSTR	GetServiceName(void) const;
	BOOL	GetServicePath(PWSTR pBuffer, DWORD bufferSize) const;
	BOOL	ChangeServicePath(PCWSTR pBinPath) const;
	BOOL	ChangeServiceStartType(DWORD dwStartType) const;
	BOOL	SetRestartOnFail();

protected:
	WCHAR m_serviceName[MAX_PATH];
};

#include "pch.h"

#include <Windows.h>

#include "ServiceHelper.h"

#include <tchar.h>
#include <strsafe.h>
#include <Winsvc.h>
#include <AclAPI.h>
#pragma comment (lib, "Advapi32.lib")

/////////////////////////////////////////////////////////////////////////////
CServiceHelper::CServiceHelper(PCWSTR pServiceName)
{
    size_t serviceNameSize = 0;
    StringCbLength(pServiceName, MAX_PATH*sizeof(WCHAR), &serviceNameSize);
	HRESULT hr = StringCbCopyW(m_serviceName, serviceNameSize+sizeof(WCHAR), pServiceName);
	if (FAILED(hr))
	{
		throw hr;
	}
}

/////////////////////////////////////////////////////////////////////////////
CServiceHelper::~CServiceHelper(void)
{
}

/////////////////////////////////////////////////////////////////////////////
BOOL CServiceHelper::Create(PCWSTR pModulePath, BOOL driver, BOOL autoStart, BOOL start) const
{
	BOOL success = FALSE;
	SC_HANDLE scm = OpenSCManagerW(NULL, NULL, SC_MANAGER_ALL_ACCESS);
	if (!scm)
	{
        return FALSE;
    }
    else
    {
		SC_HANDLE service = CreateServiceW(
								scm,
								m_serviceName,
								m_serviceName,
								SERVICE_ALL_ACCESS,
								driver ? SERVICE_KERNEL_DRIVER : SERVICE_WIN32_OWN_PROCESS,
								autoStart ? SERVICE_AUTO_START : SERVICE_DEMAND_START,
								SERVICE_ERROR_NORMAL,
								pModulePath,
								NULL,
								NULL,
								NULL,
								NULL,
								NULL
								);
		if (service)
		{
			success = TRUE;
		}
		else if (GetLastError() == ERROR_SERVICE_EXISTS)
		{
			success = TRUE;
		}

		if (success)
		{
			if (start)
			{
				if (!StartServiceW(service, 0, NULL))
				{
					if (GetLastError() == ERROR_SERVICE_ALREADY_RUNNING)
					{
                        success = TRUE;
                    }
				}
			}
		
			CloseServiceHandle(service);
		}

		CloseServiceHandle(scm);
	}

	return success;
}

/////////////////////////////////////////////////////////////////////////////
BOOL CServiceHelper::Delete(void) const
{
	Stop();

	BOOL success = FALSE;
	SC_HANDLE scm = OpenSCManagerW(NULL, NULL, SC_MANAGER_ALL_ACCESS);
	if (!scm)
	{
        return FALSE;
    }
    else
    {
		SC_HANDLE service = OpenServiceW(scm, m_serviceName, SERVICE_ALL_ACCESS);
		if (service)
		{
			success = DeleteService(service);
			CloseServiceHandle(service);
		}
		
        CloseServiceHandle(scm);

		DWORD startTime = GetTickCount();

		// 삭제 후 바로 서비스 존재 확인 시 존재하는것으로 나온다
		// 시스템에 따라 서비스 삭제에 시간이 걸릴 경우가 존재하여 대기로직 추가
		while (IsExists())
		{
			if (GetTickCount() - startTime >= 1000)
			{
				break;
			}

			Sleep(500);
		}
	}

	return success;
}

/////////////////////////////////////////////////////////////////////////////
BOOL CServiceHelper::Start(PCWSTR pParam1, PCWSTR pParam2, PCWSTR pParam3) const
{
	BOOL success = FALSE;
	SC_HANDLE scm = OpenSCManagerW(NULL, NULL, SC_MANAGER_CONNECT);
	if (!scm)
	{
        return FALSE;
    }
    else
    {
		SC_HANDLE service = OpenServiceW(scm, m_serviceName, SERVICE_START | SERVICE_USER_DEFINED_CONTROL);		
		if (service)
		{
			PCWSTR* pParams = NULL;
			PCWSTR pParamVector[4] = {NULL};
			DWORD paramCount = 0;

			if (pParam1 && pParam2 && pParam3)
			{		
				pParamVector[0] = m_serviceName;
				pParamVector[1] = pParam1;
                pParamVector[2] = pParam2;
                pParamVector[3] = pParam3;
				pParams = pParamVector;
				paramCount = sizeof(pParamVector)/sizeof(pParamVector[0]);
			}

			if (StartServiceW(service, paramCount, pParams))
            {
                success = TRUE;
            }
            else
			{
				if (GetLastError() == ERROR_SERVICE_ALREADY_RUNNING)
				{
					success = TRUE;
				}
			}
			
		
			CloseServiceHandle(service);
		}

		CloseServiceHandle(scm);
	}

	return success;
}

/////////////////////////////////////////////////////////////////////////////
BOOL CServiceHelper::Stop(DWORD timeOut) const
{
	BOOL success = FALSE;
	SC_HANDLE scm = OpenSCManagerW(NULL, NULL, SC_MANAGER_CONNECT);
	if (!scm)
	{
		return FALSE;
	}
	else
	{
		SC_HANDLE service = OpenServiceW(scm, m_serviceName, SERVICE_STOP | SERVICE_QUERY_STATUS);		
		if (service != NULL)
		{
			SERVICE_STATUS_PROCESS ssp;
			DWORD bytesNeeded = 0;

			if (QueryServiceStatusEx(service, SC_STATUS_PROCESS_INFO, (LPBYTE)&ssp, sizeof(SERVICE_STATUS_PROCESS), &bytesNeeded))
			{
				DWORD startTime = GetTickCount();

				if (ssp.dwCurrentState == SERVICE_RUNNING)
				{
					ControlService(service, SERVICE_CONTROL_STOP, (LPSERVICE_STATUS)&ssp);
					Sleep(ssp.dwWaitHint);

					while (ssp.dwCurrentState != SERVICE_STOPPED)
					{
						if (GetTickCount() - startTime >= timeOut)
						{
							break;
						}

						Sleep(ssp.dwWaitHint);
						QueryServiceStatusEx(service, SC_STATUS_PROCESS_INFO, (LPBYTE)&ssp, sizeof(SERVICE_STATUS_PROCESS), &bytesNeeded);
					}					
				}

				if (ssp.dwCurrentState == SERVICE_STOPPED)
				{
					success = TRUE;
				}
			}
			
			CloseServiceHandle(service);
		}

		CloseServiceHandle(scm);
	}

	return success;
}

/////////////////////////////////////////////////////////////////////////////
BOOL CServiceHelper::IsRunning(void) const
{
	BOOL running = FALSE;
	SC_HANDLE scm = OpenSCManagerW(NULL, NULL, SC_MANAGER_CONNECT);
	if (scm == NULL)
	{
		return FALSE;
	}
	else
	{
		SC_HANDLE service = OpenServiceW(scm, m_serviceName, SERVICE_QUERY_STATUS);		
		if (service != NULL)
		{
			SERVICE_STATUS_PROCESS ssp;
			DWORD bytesNeeded = 0;

			if (QueryServiceStatusEx(service, SC_STATUS_PROCESS_INFO, (LPBYTE)&ssp, sizeof(SERVICE_STATUS_PROCESS), &bytesNeeded))
			{
				running = (ssp.dwCurrentState == SERVICE_RUNNING);
			}
			
			CloseServiceHandle(service);
		}

		CloseServiceHandle(scm);
	}

	return running;
}

/////////////////////////////////////////////////////////////////////////////
BOOL CServiceHelper::WaitStatus(DWORD waitForServiceStatus, DWORD timeOut) const
{
	BOOL stoped = FALSE;
	SC_HANDLE scm = OpenSCManagerW(NULL, NULL, SC_MANAGER_CONNECT);
	if (scm == NULL)
	{
		return FALSE;
	}
	else
	{
		SC_HANDLE service = OpenServiceW(scm, m_serviceName, SERVICE_QUERY_STATUS);		
		if (service != NULL)
		{
			SERVICE_STATUS_PROCESS ssp;
			DWORD bytesNeeded = 0;
            DWORD startTime = GetTickCount();
            do
            {
			    if (QueryServiceStatusEx(service, SC_STATUS_PROCESS_INFO, (LPBYTE)&ssp, sizeof(SERVICE_STATUS_PROCESS), &bytesNeeded))
			    {
				    stoped = (ssp.dwCurrentState == waitForServiceStatus);
			    }
                if (stoped)
                {
                    break;
                }
                if (GetTickCount() - startTime >= timeOut)
                {
                    break;
                }

                Sleep(ssp.dwWaitHint);

            } while (TRUE);
			
            Sleep(500);

			CloseServiceHandle(service);
		}

		CloseServiceHandle(scm);
	}

	return stoped;
}

/////////////////////////////////////////////////////////////////////////////
BOOL CServiceHelper::IsExists(void) const
{
	BOOL exist = FALSE;
	SC_HANDLE scm = OpenSCManagerW(NULL, NULL, SC_MANAGER_CONNECT);
	if (scm)
	{
		SC_HANDLE service = OpenServiceW(scm, m_serviceName, SERVICE_QUERY_STATUS);		
		if (service)
		{
			exist = TRUE;
			CloseServiceHandle(service);
		}
	
		CloseServiceHandle(scm);
	}

	return exist;
}

/////////////////////////////////////////////////////////////////////////////
DWORD CServiceHelper::GetCurrentStatus(void) const
{
	DWORD retStatus = 0;
	SC_HANDLE scm = OpenSCManagerW(NULL, NULL, SC_MANAGER_CONNECT);
	if (scm == NULL)
	{
		return FALSE;
	}
	else
	{
		SC_HANDLE service = OpenServiceW(scm, m_serviceName, SERVICE_QUERY_STATUS);		
		if (service != NULL)
		{
			SERVICE_STATUS_PROCESS ssp;
			DWORD bytesNeeded = 0;
            DWORD startTime = GetTickCount();
			if (QueryServiceStatusEx(service, SC_STATUS_PROCESS_INFO, (LPBYTE)&ssp, sizeof(SERVICE_STATUS_PROCESS), &bytesNeeded))
			{
				retStatus = ssp.dwCurrentState;
			}

			CloseServiceHandle(service);
		}

		CloseServiceHandle(scm);
	}

	return retStatus;
}

/////////////////////////////////////////////////////////////////////////////
PCTSTR	CServiceHelper::GetServiceName(void) const
{
	return m_serviceName;
}

/////////////////////////////////////////////////////////////////////////////
BOOL CServiceHelper::GetServicePath(PWSTR pBuffer, DWORD bufferSize) const
{
	BOOL success = FALSE;

	SC_HANDLE scm = OpenSCManagerW(NULL, NULL, SC_MANAGER_ALL_ACCESS);
	if (scm)
	{
		SC_HANDLE service = OpenServiceW(scm, m_serviceName, SERVICE_QUERY_CONFIG);
		if (service)
		{
			LPQUERY_SERVICE_CONFIG pSvcConfig = (LPQUERY_SERVICE_CONFIG )LocalAlloc(LPTR, 4096);
			DWORD bytesNeed = 0;

			if (QueryServiceConfigW(service, pSvcConfig, 4096, &bytesNeed))
			{
				StringCbCopyW(pBuffer, bufferSize, pSvcConfig->lpBinaryPathName);
				success = TRUE;
			}

			LocalFree(pSvcConfig);

			CloseServiceHandle(service);
		}

		CloseServiceHandle(scm);
	}
	
	return success;
}

/////////////////////////////////////////////////////////////////////////////
BOOL CServiceHelper::ChangeServicePath(PCWSTR pBinPath) const
{
	BOOL success = FALSE;

	SC_HANDLE scm = OpenSCManagerW(NULL, NULL, SC_MANAGER_ALL_ACCESS);
	if (scm)
	{
		SC_HANDLE service = OpenServiceW(scm, m_serviceName, SERVICE_QUERY_CONFIG | SERVICE_CHANGE_CONFIG);
		if (service)
		{
			LPQUERY_SERVICE_CONFIG pSvcConfig = (LPQUERY_SERVICE_CONFIG)LocalAlloc(LPTR, 4096);
			DWORD bytesNeed = 0;
			if (QueryServiceConfigW(service, pSvcConfig, 4096, &bytesNeed))
			{
				success = ChangeServiceConfigW(
								service,
								pSvcConfig->dwServiceType,
								pSvcConfig->dwStartType,
								pSvcConfig->dwErrorControl,
								pBinPath,
								NULL,
								NULL,
								NULL,
								NULL,
								NULL,
								NULL
								);
			}

			LocalFree(pSvcConfig);

			CloseServiceHandle(service);
		}

		CloseServiceHandle(scm);
	}
	
	return success;
}

/////////////////////////////////////////////////////////////////////////////
BOOL CServiceHelper::ChangeServiceStartType(DWORD dwStartType) const
{
	BOOL success = FALSE;

	SC_HANDLE scm = OpenSCManagerW(NULL, NULL, SC_MANAGER_ALL_ACCESS);
	if (scm)
	{
		SC_HANDLE service = OpenServiceW(scm, m_serviceName, SERVICE_QUERY_CONFIG | SERVICE_CHANGE_CONFIG);
		if (service)
		{
			LPQUERY_SERVICE_CONFIG pSvcConfig = (LPQUERY_SERVICE_CONFIG)LocalAlloc(LPTR, 4096);
			DWORD bytesNeed = 0;
			if (QueryServiceConfigW(service, pSvcConfig, 4096, &bytesNeed))
			{
				success = ChangeServiceConfigW(
								service,
								pSvcConfig->dwServiceType,
								dwStartType,
								pSvcConfig->dwErrorControl,
								NULL,
								NULL,
								NULL,
								NULL,
								NULL,
								NULL,
								NULL
								);
			}

			LocalFree(pSvcConfig);

			CloseServiceHandle(service);
		}

		CloseServiceHandle(scm);
	}
	
	return success;
}

/////////////////////////////////////////////////////////////////////////////
BOOL CServiceHelper::SendControlCode(DWORD dwCtrlCode) const
{

	BOOL success = FALSE;
	SC_HANDLE scm = OpenSCManagerW(NULL, NULL, SC_MANAGER_CONNECT);
	if (scm)
    {
		SC_HANDLE service = OpenServiceW(scm, m_serviceName, SERVICE_STOP | SERVICE_USER_DEFINED_CONTROL);		
		if (service)
		{
			SERVICE_STATUS_PROCESS ssp;
			if (ControlService(service, dwCtrlCode, (LPSERVICE_STATUS)&ssp))
			{
				success = TRUE;
			}
		
			CloseServiceHandle(service);
		}

		CloseServiceHandle(scm);
	}
	
	return success;
}


BOOL CServiceHelper::SetRestartOnFail()
{
	BOOL success = FALSE;
	SC_HANDLE scm = NULL;
	SC_HANDLE service = NULL;
	
	do
	{
		if(NULL == (scm = OpenSCManagerW(NULL, NULL, SC_MANAGER_ALL_ACCESS)))
		{
			break;
		}


		if(NULL == (service = OpenServiceW(scm, m_serviceName, SERVICE_ALL_ACCESS/*SERVICE_QUERY_CONFIG | SERVICE_CHANGE_CONFIG*/)))
		{
			break;
		}
		
		SERVICE_FAILURE_ACTIONS sfAction;
		SC_ACTION	saA;
		/* 서비스 비정상 종료시 자동 복구 하도록 설정 */
		saA.Type = SC_ACTION_RESTART;
		saA.Delay = 500;

		sfAction.dwResetPeriod = 0;
		sfAction.lpRebootMsg = NULL;
		sfAction.lpCommand = NULL;
		sfAction.cActions = 1;
		sfAction.lpsaActions = &saA;

		if(FALSE == ChangeServiceConfig2(service, SERVICE_CONFIG_FAILURE_ACTIONS, &sfAction))
		{
			break;
		}

		success = TRUE;

	}while(FALSE);
	
	
	if(service)
		CloseServiceHandle(service);
	
	if(scm)
		CloseServiceHandle(scm);

	return success;
}

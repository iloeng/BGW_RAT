// DataStatus.cpp : implementation file
//
#include "stdafx.h"
#include "DataStatus.h"
#include <afxinet.h>
#include <afxwin.h>
#include "Gh0st.h"



#ifdef _DEBUG
#define new DEBUG_NEW
#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#endif

/////////////////////////////////////////////////////////////////////////////
// CDataStatus dialog


CDataStatus::CDataStatus(CWnd* /*pParent /*=NULL*/)

{
    //{{AFX_DATA_INIT(CDataStatus)
    //}}AFX_DATA_INIT
}


void CDataStatus::DoDataExchange(CDataExchange* pDX)
{
    CDialogBar::DoDataExchange(pDX);
    //{{AFX_DATA_MAP(CDataStatus)
    DDX_Control(pDX, IDC_GUNDONGWEB, m_gundonweb);
    DDX_Control(pDX, IDC_GUNDON, m_gundon);
    DDX_Control(pDX, IDC_DAY, m_day);
    DDX_Control(pDX, IDC_NIGHT, m_night);
    DDX_Text(pDX, IDC_Men, m_Men);
//	DDX_Control(pDX, IDC_GIFFIRST, m_Picture);
    //}}AFX_DATA_MAP
    DDX_Control(pDX, IDC_EDIT1, m_edt1);	//LED����
}


BEGIN_MESSAGE_MAP(CDataStatus, CDialogBar)
//{{AFX_MSG_MAP(CDataStatus)
    ON_MESSAGE(WM_INITDIALOG, OnInitDialog)
    ON_WM_PAINT()
    ON_WM_TIMER()
    ON_WM_CTLCOLOR()

// NOTE: the ClassWizard will add message map macros here
//}}AFX_MSG_MAP
END_MESSAGE_MAP()

/////////////////////////////////////////////////////////////////////////////
void TransParentDC(CRect rect,CDC * pDC)
{
    CDC m_MemDC;
    m_MemDC.CreateCompatibleDC(pDC);
    CBitmap m_Bitmap;
    m_Bitmap.CreateCompatibleBitmap
    (pDC,rect.Width(),rect.Height());
    CBitmap *pOldBitmap =
        m_MemDC.SelectObject(&m_Bitmap);
    m_MemDC.FillSolidRect(0,0,rect.Width(),
                          rect.Height(),GetSysColor(COLOR_MENU));

    COLORREF cor =  pDC->GetPixel(0,0);
    for(int y = 0; y < rect.Height(); y++) {
        for(int x = 0; x < rect.Width(); x++) {
            COLORREF ch = pDC->GetPixel(x,y);
            if(ch != cor)
                m_MemDC.SetPixelV(x,y,ch);
        }
    }
    pDC->BitBlt(0,0,rect.Width(),
                rect.Height(),&m_MemDC,0,0,SRCCOPY);
    m_MemDC.SelectObject(pOldBitmap);
    m_Bitmap.DeleteObject();
}

CSize CDataStatus::LoadMyBitmap(UINT nID)
{
    CDC * pDC = GetDC();
    CDC m_MemDC;
    m_MemDC.CreateCompatibleDC(pDC);
    CSize m_Size = pDC->GetTextExtent("ˢ��");
    ReleaseDC(pDC);
    CRect rect(0,0,60,32);
    CBitmap *pBitmap,*pOldBitmap;
    pBitmap = new CBitmap;
    pBitmap->LoadBitmap(nID);
    pOldBitmap = m_MemDC.SelectObject(pBitmap);
    TransParentDC(rect,&m_MemDC);
    m_MemDC.SelectObject(pOldBitmap);
    m_ToolBarList.Add(pBitmap,GetSysColor(COLOR_MENU));
    pBitmap->DeleteObject();
    delete pBitmap;
    return m_Size;
}
// CDataStatus message handlers
void CDataStatus::OnPaint()
{


    CPaintDC dc(this); // device context for painting

    // TODO: Add your message handler code here
    CFont	*pFont = new CFont();
    pFont->CreateFont(0,0,0,0,FW_BOLD,0,0,0,DEFAULT_CHARSET,OUT_DEFAULT_PRECIS,
                      CLIP_DEFAULT_PRECIS,DEFAULT_QUALITY,DEFAULT_PITCH,_T("����"));

    GetDlgItem(IDC_CITY)->SetFont(pFont,TRUE);

    delete pFont;



    // Do not call CDialog::OnPaint() for painting messages
}

LONG CDataStatus::OnInitDialog(UINT wParam, LONG lParam)
{

    BOOL bRet = HandleInitDialog(wParam, lParam);
    if(!UpdateData(FALSE)) {
        TRACE0("Warning, Unalbe to init update.\n");
    }

    GetWeather();

    if (!m_wndToolBar.CreateEx(this, TBSTYLE_FLAT, WS_CHILD | WS_VISIBLE | CBRS_TOP //CBRS_LEFT
                               | CBRS_GRIPPER | CBRS_TOOLTIPS | CBRS_FLYBY | CBRS_SIZE_DYNAMIC) ||
        !m_wndToolBar.LoadToolBar(IDR_TOOLBAR_MAIN)) {
        TRACE0("Failed to create toolbar\n");
        return -1;      // fail to create
    }

    //�������������������ж�
    // 	m_wndToolBar.EnableDocking(CBRS_ALIGN_ANY); //���������ڹ������������ƶ�
    // 	EnableDocking(CBRS_ALIGN_ANY);  //�˿���κεط�������϶�������Ѿ�Ϊ���ToolBarд�����Բ�����д
    //	DockControlBar(&m_wndToolBar); //����˹�����������window�������϶�

    m_ToolBarList.Create(60,36,ILC_COLOR24|ILC_MASK,0,0);
    CSize m_Size =
        LoadMyBitmap(IDB_BITMAP_XTSZ);
    LoadMyBitmap(IDB_BITMAP_FWSC);
    LoadMyBitmap(IDB_BITMAP_SYGJ);
    LoadMyBitmap(IDB_BITMAP_GXYM);
    LoadMyBitmap(IDB_BITMAP_GYCX);
    m_wndToolBar.SetButtonText(0,_T("ϵͳ����"));
    m_wndToolBar.SetButtonText(1,_T("��������"));
    m_wndToolBar.SetButtonText(2,_T("ʵ�ù���"));
    m_wndToolBar.SetButtonText(3,_T("��������"));
    m_wndToolBar.SetButtonText(4,_T("���ڳ���"));

    m_wndToolBar.GetToolBarCtrl().SetImageList(&m_ToolBarList);
    m_wndToolBar.GetToolBarCtrl().SetDisabledImageList(&m_ToolBarList);
    m_wndToolBar.GetToolBarCtrl().SetButtonSize(CSize(60,34 + m_Size.cy + 5));
    m_wndToolBar.GetToolBarCtrl().SetBitmapSize(CSize(60,33));

    // 	if (m_Picture.Load(MAKEINTRESOURCE(IDR_TUTU),_T("GIF")))   //��ʾGIFͼƬ
    // 	m_Picture.Draw();

    RepositionBars(AFX_IDW_CONTROLBAR_FIRST, AFX_IDW_CONTROLBAR_LAST, 0); //��ʾ״̬��
    m_gundon.GetClientRect(m_rect_parent);
    m_gundonweb.GetClientRect(m_rect_web);
    m_gundonweb.SetParent(&m_gundon);
    CurRect.DeflateRect(0,1,m_rect_parent.Width()-m_rect_web.Width(),1);
    m_gundonweb.MoveWindow(m_rect_parent);
    SetTimer(1,30,NULL);//���������ַ��ٶ�
    // Add Code here
    OnTimer( 30);
    m_gundonweb.MoveWindow(m_rect_web);
    // Add Code here
    TCHAR szBuffer[256];
    DWORD dwSize=256;
    GetComputerName(szBuffer,&dwSize);
    m_Men=szBuffer;
    MEMORYSTATUS mem_stat;
    GlobalMemoryStatus(&mem_stat);
    m_Men.Format("%d %%",mem_stat.dwMemoryLoad);
    UpdateData(FALSE);
    return bRet;
}

HBRUSH CDataStatus::OnCtlColor(CDC* pDC, CWnd* pWnd, UINT nCtlColor)        // ��Ϣ��Ӧ����ʵ��
{

    if ((pWnd->GetDlgCtrlID() == IDC_CITY)) {
        COLORREF clr = RGB(242, 0, 6);
        pDC->SetTextColor(clr);   //���ð�ɫ���ı�
        clr = RGB(240,240,240);
        pDC->SetBkColor(clr);     //���ú�ɫ�ı���
        return CreateSolidBrush(clr);  //��ΪԼ�������ر���ɫ��Ӧ��ˢ�Ӿ��
    }

    if ((pWnd->GetDlgCtrlID() == IDC_WENDU)) {
        COLORREF clr = RGB(250, 0, 0);
        pDC->SetTextColor(clr);   //���ð�ɫ���ı�
        clr = RGB(240,240,240);
        pDC->SetBkColor(clr);     //���ú�ɫ�ı���
        return CreateSolidBrush(clr);  //��ΪԼ�������ر���ɫ��Ӧ��ˢ�Ӿ��
    }
    if ((pWnd->GetDlgCtrlID() == IDC_TIANQI)) {
        COLORREF clr = RGB(37, 0, 251);
        pDC->SetTextColor(clr);   //���ð�ɫ���ı�
        clr = RGB(240,240,240);
        pDC->SetBkColor(clr);     //���ú�ɫ�ı���
        return CreateSolidBrush(clr);  //��ΪԼ�������ر���ɫ��Ӧ��ˢ�Ӿ��
    }

    if ((pWnd->GetDlgCtrlID() == IDC_FENGSU)) {
        COLORREF clr = RGB(37, 0, 251);
        pDC->SetTextColor(clr);   //���ð�ɫ���ı�
        clr = RGB(240,240,240);
        pDC->SetBkColor(clr);     //���ú�ɫ�ı���
        return CreateSolidBrush(clr);  //��ΪԼ�������ر���ɫ��Ӧ��ˢ�Ӿ��
    }

// 	if ((pWnd->GetDlgCtrlID() == IDC_GUNDON))
// 	{
// 		COLORREF clr = RGB(37, 0, 251);
// 		pDC->SetTextColor(clr);   //���ð�ɫ���ı�
// 		clr = RGB(240,240,240);
// 		pDC->SetBkColor(clr);     //���ú�ɫ�ı���
// 		return CreateSolidBrush(clr);  //��ΪԼ�������ر���ɫ��Ӧ��ˢ�Ӿ��
// 	}
    return 0;
}

void CDataStatus::OnTimer(UINT nIDEvent)
{
    //��ʾʱ��
    CString ww;
    CTime time=CTime::GetCurrentTime();
    ww=time.Format("%Y-%m-%d %H:%M:%S");//ת��ʱ���ʽ

    //m_edt1.SetColor(RGB(255,255,255),RGB(0,0,255));	//������ɫ(���ֱ���ɫ,ǰ��ɫ)
    //m_edt1.SetBkColor(RGB(255,255,0));	//�ؼ�����ɫ
    m_edt1.SetColor(RGB(255,255,255),RGB(0,0,0));	//������ɫ(���ֱ���ɫ,ǰ��ɫ)
    m_edt1.SetBkColor(RGB(255,255,255));	//�ؼ�����ɫ
    m_edt1.SetText(ww);

    CWnd::OnTimer(nIDEvent);
    ///
    if (m_rect_web.right<=m_rect_parent.left) {
        m_rect_web.left = m_rect_parent.right;
        m_rect_web.right = m_rect_parent.right-m_rect_web.Width();


    } else {
        m_rect_web.left-=2;
        m_rect_web.right-=2;

    }
    //�����ؼ�λ��
    m_gundonweb.MoveWindow(m_rect_web);



}

int URLEncode(LPCTSTR pszUrl, LPTSTR pszEncode, int nEncodeLen)
{
    if (pszUrl == NULL)
        return 0;

    if (pszEncode == NULL || nEncodeLen == 0)
        return 0;

    //�������
    int nLength = 0;
    WCHAR* pWString = NULL;
    TCHAR* pString = NULL;

    //�Ƚ��ַ����ɶ��ֽ�ת����UTF-8����
    nLength = MultiByteToWideChar(CP_ACP, 0, pszUrl, -1, NULL, 0);

    //����Unicode�ռ�
    pWString = new WCHAR[nLength];

    //��ת����Unicode
    MultiByteToWideChar(CP_ACP, 0, pszUrl, -1, pWString, nLength);

    //����UTF-8�ռ�
    nLength = WideCharToMultiByte(CP_UTF8, 0, pWString, -1, NULL, 0, NULL, NULL);
    pString = new TCHAR[nLength];

    //Unicodeת��UTF-8
    nLength = WideCharToMultiByte(CP_UTF8, 0, pWString, -1, pString, nLength, NULL, NULL);

    static char hex[] = { '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F' };
    memset(pszEncode, 0, nEncodeLen / sizeof(TCHAR));

    for (int i = 0; i < nLength - 1; i++) {
        unsigned char c = pString[i];
        if (c > 0x20 && c < 0x7f) {  // ���ֻ���ĸ
            *pszEncode++ = c;
        } else if (c == 0x20) {    // �����ո�
            *pszEncode++ = '+';
        } else {                    // ���б���
            *pszEncode++ = '%';
            *pszEncode++ = hex[c / 16];
            *pszEncode++ = hex[c % 16];
        }
    }

    //ɾ���ڴ�
    delete pWString;
    delete pString;

    return nLength;
}

//Ѱ���ַ������� yesNO�Ƿ�Ҫɾ���ҵ���ǰ�������ַ�
CString CDataStatus::FindStr(CString &str,CString strFind1,CString strFind2,bool yesNo)
{
    int nFirst;
    int nEnd;
    CString strTemp;
    nFirst = str.Find(strFind1);
    nEnd = str.Find(strFind2);
    strTemp = str.Mid(nFirst+_tcslen(strFind1),nEnd-nFirst-_tcslen(strFind1));
    if (yesNo) {
        str = str.Right(_tcslen(str)-(nEnd + _tcslen(strFind2)));
    }

    return strTemp;
}



//��ȡ������Դ  ��л (��)�ᴳ�����ṩ�Ĳο�����
// void CDataStatus::SavePng(CString strUrl,CString strPath)
// {
// 	CInternetSession Session;
// 	CString strServerName,strObject;
// 	DWORD dwSvrType;
// 	INTERNET_PORT nPort;
// 	AfxParseURL(strUrl,dwSvrType,strServerName,strObject,nPort);
// 	const TCHAR szHeaders[] = _T("application/x-shockwave-flash, image/gif, image/x-xbitmap, image/jpeg, image/pjpeg, application/vnd.ms-excel, application/vnd.ms-powerpoint, application/msword, application/xaml+xml, application/vnd.ms-xpsdocument, application/x-ms-xbap, application/x-ms-application, */*");
// 	CHttpConnection *pConnection = Session.GetHttpConnection(strServerName,nPort);
// 	if (!pConnection)
// 	{
// 		MessageBox(_T("���ӷ�����ʧ��"));
// 	}
// 	CHttpFile *pHttpFile;
// 	try
// 	{
// 		pHttpFile = (CHttpFile *)pConnection->OpenRequest(
// 			CHttpConnection::HTTP_VERB_GET,
// 			strObject,
// 			NULL,1,NULL,NULL,
// 			INTERNET_FLAG_NO_COOKIES|INTERNET_FLAG_KEEP_CONNECTION|INTERNET_FLAG_NO_AUTO_REDIRECT
// 			);
// 	}
// 	catch(CException *e)
// 	{
// 		pHttpFile = NULL;
// 		throw;
// 	}
// 	if (pHttpFile)
// 	{
// 		DWORD dwStatus = 0;
// 		BOOL bSuccess;
// 		try
// 		{
// 			pHttpFile->AddRequestHeaders(szHeaders);
// 			pHttpFile->SendRequest();
// 			bSuccess = pHttpFile->QueryInfoStatusCode(dwStatus);
// 		}
// 		catch(...)
// 		{
// 			delete pHttpFile;
// 			delete pConnection;
// 			return;
// 		}
// 		char strarray[1024];
// 		if (bSuccess && (dwStatus >= 200 && dwStatus <=300))
// 		{
// 			//CString sFileName = GetUrlName
// 			CString strContentType = _T("");
// 			//text/html
// 			pHttpFile->QueryInfo(HTTP_QUERY_CONTENT_TYPE,strContentType);
// 			CFile NetFile;
// 			if (NetFile.Open(strPath,CFile::modeWrite|CFile::modeCreate))
// 			{
// 				int nCount = 0;
// 				nCount = pHttpFile->Read(strarray,1023);
// 				while (nCount>0)
// 				{
// 					NetFile.Write(strarray,nCount);
// 					nCount = pHttpFile->Read(strarray,1023);
// 				}
// 				NetFile.Close();
// 			}
//
// 		}
//
// 	}
// 	pHttpFile->Close();
// 	delete pHttpFile;
//
// }


////////////////////////////////////////////////////////////////////

//�������ϻ�ȡ����
BOOL CDataStatus::GetWeather()
{
    BOOL	bRetCode = FALSE;

    CInternetSession	CSession;
    CHttpConnection		*pHttpConn = NULL;
    CHttpFile			*pHttpFile = NULL;

    DWORD	dwStatusCode = 0;	//�������״̬
    CString	strErrMsg;	//������Ϣ��ʾ
    char	szRecvBuff[256];

    try {

        //http://whois.pconline.com.cn/ip.jsp
        pHttpConn = CSession.GetHttpConnection(_T("whois.pconline.com.cn"),(INTERNET_PORT)80);
        if (pHttpConn == NULL) {
            strErrMsg = _T("����������ʧ�ܣ��޷���ȡ������Ϣ��");
            goto EXIT0;
        }
        pHttpFile = pHttpConn->OpenRequest(CHttpConnection::HTTP_VERB_GET,_T("/ipJson.jsp"));
        if (pHttpFile == NULL) {
            strErrMsg = _T("�������ϸ������ݶ�ʧ���޷���ȡ������Ϣ��");
            goto EXIT0;
        }

        if (!pHttpFile->SendRequest()) {
            strErrMsg = _T("�������������ʧ�ܣ��޷���ȡ������Ϣ��");
            goto EXIT0;
        }


        //��ѯ�������״̬
        pHttpFile->QueryInfoStatusCode(dwStatusCode);
        if (dwStatusCode != 200) {
            strErrMsg.Format(_T("��ȡ��������������ʧ�ܣ�״̬�룺%d���޷���ȡ������Ϣ"),
                             dwStatusCode);
            goto EXIT0;
        }

        //��������
        pHttpFile->Read(szRecvBuff,sizeof(szRecvBuff));

        bRetCode = TRUE;
    } catch (CInternetException* e) {
        e->Delete();
    }

EXIT0:
    //�ر���������
    pHttpFile->Close();
    delete pHttpFile;
    pHttpConn->Close();
    delete pHttpConn;
    CSession.Close();


    //�����������û�л�ȡ����Ҫ����
    if (!bRetCode) {
        return bRetCode;
    }

    //�������ݣ�������汾��
    CString	strRecv(szRecvBuff,130);
    strRecv.Delete(0,strRecv.Find(_T("city\":\"")) + _tcslen(_T("city\":\"")));
    strRecv = strRecv.Left(strRecv.Find(_T("\",\"cityCode")));
    strRecv = strRecv.IsEmpty() ? "����" : strRecv;
    SetDlgItemText(IDC_CITY, strRecv);

    TCHAR szEncode[255];
    CString strCoding;

    URLEncode(strRecv, szEncode, sizeof(szEncode));

    strCoding = szEncode;

    CString strURL;

    strURL = _T("http://api.map.baidu.com/telematics/v3/weather?location=") + strCoding + _T("&&output=json&&ak=DC8048985ecf4db39f22016f18226a1c");

    CInternetSession mySession(NULL,0);
    CHttpFile *httpFile;
    httpFile = (CHttpFile *)mySession.OpenURL(strURL);
    if (!httpFile) {
        MessageBox(_T("��ȡ������Ϣ����"),_T(""),MB_OK);

    }
    DWORD dwStatus;
    DWORD dwBuffLen = sizeof(dwStatus);
    BOOL bSuccess;
    bSuccess = httpFile->QueryInfo(HTTP_QUERY_STATUS_CODE|HTTP_QUERY_FLAG_NUMBER,&dwStatus,&dwBuffLen);
    CString str;
    if (dwStatus >= 200 && dwStatus < 300) {
        CString strTemp;

        while (httpFile->ReadString(strTemp)) {
            str += strTemp;

        }

    }

    httpFile->Close();
    delete httpFile;
    mySession.Close();

    //uft-8 ת unicode
    CString wData;
    WCHAR *wword;
    DWORD num = MultiByteToWideChar(CP_UTF8,0,(LPCSTR)str.GetBuffer(0),-1,NULL,0);
    wword = (WCHAR*)calloc(num,sizeof(WCHAR));
    memset(wword, 0, num*sizeof(WCHAR));
    MultiByteToWideChar(CP_UTF8,0,(LPCSTR)str.GetBuffer(0),-1,wword,num);
    str.ReleaseBuffer();
    wData = wword;


    m_1= "��"+FindStr(wData,_T("des\":\""),_T("\"},{\"title"),true)+"��";
    m_2= "��"+FindStr(wData,_T("des\":\""),_T("\"},{\"title"),true)+"��";
    m_3= "��"+FindStr(wData,_T("des\":\""),_T("\"},{\"title"),true)+"��";
    m_strgundon = "��  "+FindStr(wData,_T("des\":\""),_T("\"},{\"title"),true);

    SetDlgItemText(IDC_GUNDONGWEB,m_strgundon);


    m_strwendu = FindStr(wData,_T("[{\"date\":\""),_T("\",\"dayPictureUrl"),true);
    SetDlgItemText(IDC_WENDU,m_strwendu);


    m_strtianqi = FindStr(wData,_T("weather\":\""),_T("\",\"wind"),true);
    SetDlgItemText(IDC_TIANQI,m_strtianqi);

    //  m_strNewUrl1 = FindStr(wData,_T("dayPictureUrl\":\""),_T("\",\"night"),true);
    // 	m_strNewUrl2 = FindStr(wData,_T("Url\":\""),_T("\",\"weather"),true);

    m_strfengsu = FindStr(wData,_T("wind\":\""),_T("\",\"temperature"),true) +" ( "+ FindStr(wData,_T("temperature\":\""),_T("\"},{\"date"),true) +" ) ";
    SetDlgItemText(IDC_FENGSU,m_strfengsu);
    /*

    	if (m_strtianqi=="����")
    	{
    		CStatic* p1 = (CStatic*)GetDlgItem(IDC_NIGHT);
    		HICON   hIcon1   =   (HICON)::LoadImage(::AfxGetInstanceHandle(),  MAKEINTRESOURCE(IDI_NIGHT_duoyun),   IMAGE_ICON,   42,   30,   0);
    		p1->ModifyStyle(0x0,SS_ICON|SS_CENTERIMAGE);
    		p1->SetIcon(hIcon1);

    		CStatic* p2 = (CStatic*)GetDlgItem(IDC_DAY);
    		HICON   hIcon2   =   (HICON)::LoadImage(::AfxGetInstanceHandle(),  MAKEINTRESOURCE(IDI_DAY_duoyun),   IMAGE_ICON,   42,   30,   0);
    		p2->ModifyStyle(0x0,SS_ICON|SS_CENTERIMAGE);
    		p2->SetIcon(hIcon2);

    	}

    	if (m_strtianqi=="��")
    	{
    		CStatic* p3 = (CStatic*)GetDlgItem(IDC_NIGHT);
    		HICON   hIcon3   =   (HICON)::LoadImage(::AfxGetInstanceHandle(),  MAKEINTRESOURCE(IDI_NIGHT_yin),   IMAGE_ICON,   42,   30,   0);
    		p3->ModifyStyle(0x0,SS_ICON|SS_CENTERIMAGE);
    		p3->SetIcon(hIcon3);

    		CStatic* p4 = (CStatic*)GetDlgItem(IDC_DAY);
    		HICON   hIcon4   =   (HICON)::LoadImage(::AfxGetInstanceHandle(),  MAKEINTRESOURCE(IDI_DAY_yin),   IMAGE_ICON,   42,   30,   0);
    		p4->ModifyStyle(0x0,SS_ICON|SS_CENTERIMAGE);
    		p4->SetIcon(hIcon4);

    	}

    	if (m_strtianqi=="����")
    	{
    		CStatic* p5 = (CStatic*)GetDlgItem(IDC_NIGHT);
    		HICON   hIcon5   =   (HICON)::LoadImage(::AfxGetInstanceHandle(),  MAKEINTRESOURCE(IDI_NIGHT_dayu),   IMAGE_ICON,   42,   30,   0);
    		p5->ModifyStyle(0x0,SS_ICON|SS_CENTERIMAGE);
    		p5->SetIcon(hIcon5);

    		CStatic* p6 = (CStatic*)GetDlgItem(IDC_DAY);
    		HICON   hIcon6   =   (HICON)::LoadImage(::AfxGetInstanceHandle(),  MAKEINTRESOURCE(IDI_DAY_dayu),   IMAGE_ICON,   42,   30,   0);
    		p6->ModifyStyle(0x0,SS_ICON|SS_CENTERIMAGE);
    		p6->SetIcon(hIcon6);

    	}

    	if (m_strtianqi=="С��")
    	{
    		CStatic* p7 = (CStatic*)GetDlgItem(IDC_NIGHT);
    		HICON   hIcon7   =   (HICON)::LoadImage(::AfxGetInstanceHandle(),  MAKEINTRESOURCE(IDI_NIGHT_xiaoyu),   IMAGE_ICON,   42,   30,   0);
    		p7->ModifyStyle(0x0,SS_ICON|SS_CENTERIMAGE);
    		p7->SetIcon(hIcon7);

    		CStatic* p8 = (CStatic*)GetDlgItem(IDC_DAY);
    		HICON   hIcon8   =   (HICON)::LoadImage(::AfxGetInstanceHandle(),  MAKEINTRESOURCE(IDI_DAY_xiaoyu),   IMAGE_ICON,   42,   30,   0);
    		p8->ModifyStyle(0x0,SS_ICON|SS_CENTERIMAGE);
    		p8->SetIcon(hIcon8);

    	}

    	if (m_strtianqi=="��ѩ")
    	{
    		CStatic* p9 = (CStatic*)GetDlgItem(IDC_NIGHT);
    		HICON   hIcon9   =   (HICON)::LoadImage(::AfxGetInstanceHandle(),  MAKEINTRESOURCE(IDI_NIGHT_daxue),   IMAGE_ICON,   42,   30,   0);
    		p9->ModifyStyle(0x0,SS_ICON|SS_CENTERIMAGE);
    		p9->SetIcon(hIcon9);

    		CStatic* p10 = (CStatic*)GetDlgItem(IDC_DAY);
    		HICON   hIcon10   =   (HICON)::LoadImage(::AfxGetInstanceHandle(),  MAKEINTRESOURCE(IDI_DAY_daxue),   IMAGE_ICON,   42,   30,   0);
    		p10->ModifyStyle(0x0,SS_ICON|SS_CENTERIMAGE);
    		p10->SetIcon(hIcon10);

    	}

    	if (m_strtianqi=="Сѩ")
    	{
    		CStatic* p11 = (CStatic*)GetDlgItem(IDC_NIGHT);
    		HICON   hIcon11   =   (HICON)::LoadImage(::AfxGetInstanceHandle(),  MAKEINTRESOURCE(IDI_NIGHT_xiaoxue),   IMAGE_ICON,   42,   30,   0);
    		p11->ModifyStyle(0x0,SS_ICON|SS_CENTERIMAGE);
    		p11->SetIcon(hIcon11);

    		CStatic* p12 = (CStatic*)GetDlgItem(IDC_DAY);
    		HICON   hIcon12   =   (HICON)::LoadImage(::AfxGetInstanceHandle(),  MAKEINTRESOURCE(IDI_DAY_xiaoxue),   IMAGE_ICON,   42,   30,   0);
    		p12->ModifyStyle(0x0,SS_ICON|SS_CENTERIMAGE);
    		p12->SetIcon(hIcon12);

    	}

    	if (m_strtianqi=="��")
    	{
    		CStatic* p13 = (CStatic*)GetDlgItem(IDC_NIGHT);
    		HICON   hIcon13   =   (HICON)::LoadImage(::AfxGetInstanceHandle(),  MAKEINTRESOURCE(IDI_NIGHT_qing),   IMAGE_ICON,   42,   30,   0);
    		p13->ModifyStyle(0x0,SS_ICON|SS_CENTERIMAGE);
    		p13->SetIcon(hIcon13);

    		CStatic* p14 = (CStatic*)GetDlgItem(IDC_DAY);
    		HICON   hIcon14   =   (HICON)::LoadImage(::AfxGetInstanceHandle(),  MAKEINTRESOURCE(IDI_DAY_qing),   IMAGE_ICON,   42,   30,   0);
    		p14->ModifyStyle(0x0,SS_ICON|SS_CENTERIMAGE);
    		p14->SetIcon(hIcon14);

    	}

    	if (m_strtianqi=="����")
    	{
    		CStatic* p15 = (CStatic*)GetDlgItem(IDC_NIGHT);
    		HICON   hIcon15   =   (HICON)::LoadImage(::AfxGetInstanceHandle(),  MAKEINTRESOURCE(IDI_NIGHT_baoyu),   IMAGE_ICON,   42,   30,   0);
    		p15->ModifyStyle(0x0,SS_ICON|SS_CENTERIMAGE);
    		p15->SetIcon(hIcon15);

    		CStatic* p16 = (CStatic*)GetDlgItem(IDC_DAY);
    		HICON   hIcon16   =   (HICON)::LoadImage(::AfxGetInstanceHandle(),  MAKEINTRESOURCE(IDI_DAY_baoyu),   IMAGE_ICON,   42,   30,   0);
    		p16->ModifyStyle(0x0,SS_ICON|SS_CENTERIMAGE);
    		p16->SetIcon(hIcon16);

    	}

    	if (m_strtianqi=="����")
    	{
    		CStatic* p17 = (CStatic*)GetDlgItem(IDC_NIGHT);
    		HICON   hIcon17   =   (HICON)::LoadImage(::AfxGetInstanceHandle(),  MAKEINTRESOURCE(IDI_NIGHT_zhongyu),   IMAGE_ICON,   42,   30,   0);
    		p17->ModifyStyle(0x0,SS_ICON|SS_CENTERIMAGE);
    		p17->SetIcon(hIcon17);

    		CStatic* p18 = (CStatic*)GetDlgItem(IDC_DAY);
    		HICON   hIcon18   =   (HICON)::LoadImage(::AfxGetInstanceHandle(),  MAKEINTRESOURCE(IDI_DAY_zhongyu),   IMAGE_ICON,   42,   30,   0);
    		p18->ModifyStyle(0x0,SS_ICON|SS_CENTERIMAGE);
    		p18->SetIcon(hIcon18);

    	}

    	if (m_strtianqi=="����ת����")
    	{
    		CStatic* p19 = (CStatic*)GetDlgItem(IDC_NIGHT);
    		HICON   hIcon19   =   (HICON)::LoadImage(::AfxGetInstanceHandle(),  MAKEINTRESOURCE(IDI_NIGHT_zhongyuzhuandayu),   IMAGE_ICON,   42,   30,   0);
    		p19->ModifyStyle(0x0,SS_ICON|SS_CENTERIMAGE);
    		p19->SetIcon(hIcon19);

    		CStatic* p20 = (CStatic*)GetDlgItem(IDC_DAY);
    		HICON   hIcon20   =   (HICON)::LoadImage(::AfxGetInstanceHandle(),  MAKEINTRESOURCE(IDI_DAY_zhongyuzhuandayu),   IMAGE_ICON,   42,   30,   0);
    		p20->ModifyStyle(0x0,SS_ICON|SS_CENTERIMAGE);
    		p20->SetIcon(hIcon20);

    	}

    	if (m_strtianqi=="����")
    	{
    		CStatic* p21 = (CStatic*)GetDlgItem(IDC_NIGHT);
    		HICON   hIcon21   =   (HICON)::LoadImage(::AfxGetInstanceHandle(),  MAKEINTRESOURCE(IDI_NIGHT_dabaoyu),   IMAGE_ICON,   42,   30,   0);
    		p21->ModifyStyle(0x0,SS_ICON|SS_CENTERIMAGE);
    		p21->SetIcon(hIcon21);

    		CStatic* p22 = (CStatic*)GetDlgItem(IDC_DAY);
    		HICON   hIcon22   =   (HICON)::LoadImage(::AfxGetInstanceHandle(),  MAKEINTRESOURCE(IDI_DAY_dabaoyu),   IMAGE_ICON,   42,   30,   0);
    		p22->ModifyStyle(0x0,SS_ICON|SS_CENTERIMAGE);
    		p22->SetIcon(hIcon22);

    	}

    	if (m_strtianqi=="�ش���")
    	{
    		CStatic* p23 = (CStatic*)GetDlgItem(IDC_NIGHT);
    		HICON   hIcon23   =   (HICON)::LoadImage(::AfxGetInstanceHandle(),  MAKEINTRESOURCE(IDI_NIGHT_tedabaoyu),   IMAGE_ICON,   42,   30,   0);
    		p23->ModifyStyle(0x0,SS_ICON|SS_CENTERIMAGE);
    		p23->SetIcon(hIcon23);

    		CStatic* p24 = (CStatic*)GetDlgItem(IDC_DAY);
    		HICON   hIcon24   =   (HICON)::LoadImage(::AfxGetInstanceHandle(),  MAKEINTRESOURCE(IDI_DAY_tedabaoyu),   IMAGE_ICON,   42,   30,   0);
    		p24->ModifyStyle(0x0,SS_ICON|SS_CENTERIMAGE);
    		p24->SetIcon(hIcon24);

    	}

    	if (m_strtianqi=="����ת����")
    	{
    		CStatic* p25 = (CStatic*)GetDlgItem(IDC_NIGHT);
    		HICON   hIcon25   =   (HICON)::LoadImage(::AfxGetInstanceHandle(),  MAKEINTRESOURCE(IDI_NIGHT_baoyuzhuandabaoyu),   IMAGE_ICON,   42,   30,   0);
    		p25->ModifyStyle(0x0,SS_ICON|SS_CENTERIMAGE);
    		p25->SetIcon(hIcon25);

    		CStatic* p26 = (CStatic*)GetDlgItem(IDC_DAY);
    		HICON   hIcon26   =   (HICON)::LoadImage(::AfxGetInstanceHandle(),  MAKEINTRESOURCE(IDI_DAY_baoyuzhuandabaoyu),   IMAGE_ICON,   42,   30,   0);
    		p26->ModifyStyle(0x0,SS_ICON|SS_CENTERIMAGE);
    		p26->SetIcon(hIcon26);

    	}

    	if (m_strtianqi=="����ת�ش���")
    	{
    		CStatic* p27 = (CStatic*)GetDlgItem(IDC_NIGHT);
    		HICON   hIcon27   =   (HICON)::LoadImage(::AfxGetInstanceHandle(),  MAKEINTRESOURCE(IDI_NIGHT_dabaoyuzhuantedabaoyu),   IMAGE_ICON,   42,   30,   0);
    		p27->ModifyStyle(0x0,SS_ICON|SS_CENTERIMAGE);
    		p27->SetIcon(hIcon27);

    		CStatic* p28 = (CStatic*)GetDlgItem(IDC_DAY);
    		HICON   hIcon28   =   (HICON)::LoadImage(::AfxGetInstanceHandle(),  MAKEINTRESOURCE(IDI_DAY_dabaoyuzhuantedabaoyu),   IMAGE_ICON,   42,   30,   0);
    		p28->ModifyStyle(0x0,SS_ICON|SS_CENTERIMAGE);
    		p28->SetIcon(hIcon28);

    	}

    	if (m_strtianqi=="����ת����")
    	{
    		CStatic* p29 = (CStatic*)GetDlgItem(IDC_NIGHT);
    		HICON   hIcon29   =   (HICON)::LoadImage(::AfxGetInstanceHandle(),  MAKEINTRESOURCE(IDI_NIGHT_dayuzhuanbaoyu),   IMAGE_ICON,   42,   30,   0);
    		p29->ModifyStyle(0x0,SS_ICON|SS_CENTERIMAGE);
    		p29->SetIcon(hIcon29);

    		CStatic* p30 = (CStatic*)GetDlgItem(IDC_DAY);
    		HICON   hIcon30   =   (HICON)::LoadImage(::AfxGetInstanceHandle(),  MAKEINTRESOURCE(IDI_DAY_dayuzhuanbaoyu),   IMAGE_ICON,   42,   30,   0);
    		p30->ModifyStyle(0x0,SS_ICON|SS_CENTERIMAGE);
    		p30->SetIcon(hIcon30);

    	}

    	if (m_strtianqi=="����")
    	{
    		CStatic* p31 = (CStatic*)GetDlgItem(IDC_NIGHT);
    		HICON   hIcon31   =   (HICON)::LoadImage(::AfxGetInstanceHandle(),  MAKEINTRESOURCE(IDI_NIGHT_zhenyu),   IMAGE_ICON,   42,   30,   0);
    		p31->ModifyStyle(0x0,SS_ICON|SS_CENTERIMAGE);
    		p31->SetIcon(hIcon31);

    		CStatic* p32 = (CStatic*)GetDlgItem(IDC_DAY);
    		HICON   hIcon32   =   (HICON)::LoadImage(::AfxGetInstanceHandle(),  MAKEINTRESOURCE(IDI_DAY_zhenyu),   IMAGE_ICON,   42,   30,   0);
    		p32->ModifyStyle(0x0,SS_ICON|SS_CENTERIMAGE);
    		p32->SetIcon(hIcon32);

    	}

    	if (m_strtianqi=="������")
    	{
    		CStatic* p33 = (CStatic*)GetDlgItem(IDC_NIGHT);
    		HICON   hIcon33   =   (HICON)::LoadImage(::AfxGetInstanceHandle(),  MAKEINTRESOURCE(IDI_NIGHT_leizhenyu),   IMAGE_ICON,   42,   30,   0);
    		p33->ModifyStyle(0x0,SS_ICON|SS_CENTERIMAGE);
    		p33->SetIcon(hIcon33);

    		CStatic* p34 = (CStatic*)GetDlgItem(IDC_DAY);
    		HICON   hIcon34   =   (HICON)::LoadImage(::AfxGetInstanceHandle(),  MAKEINTRESOURCE(IDI_DAY_leizhenyu),   IMAGE_ICON,   42,   30,   0);
    		p34->ModifyStyle(0x0,SS_ICON|SS_CENTERIMAGE);
    		p34->SetIcon(hIcon34);

    	}

    	if (m_strtianqi=="����")
    	{
    		CStatic* p35 = (CStatic*)GetDlgItem(IDC_NIGHT);
    		HICON   hIcon35   =   (HICON)::LoadImage(::AfxGetInstanceHandle(),  MAKEINTRESOURCE(IDI_NIGHT_dongyu),   IMAGE_ICON,   42,   30,   0);
    		p35->ModifyStyle(0x0,SS_ICON|SS_CENTERIMAGE);
    		p35->SetIcon(hIcon35);

    		CStatic* p36 = (CStatic*)GetDlgItem(IDC_DAY);
    		HICON   hIcon36   =   (HICON)::LoadImage(::AfxGetInstanceHandle(),  MAKEINTRESOURCE(IDI_DAY_dongyu),   IMAGE_ICON,   42,   30,   0);
    		p36->ModifyStyle(0x0,SS_ICON|SS_CENTERIMAGE);
    		p36->SetIcon(hIcon36);

    	}

    	if (m_strtianqi=="��������б���")
    	{
    		CStatic* p37 = (CStatic*)GetDlgItem(IDC_NIGHT);
    		HICON   hIcon37   =   (HICON)::LoadImage(::AfxGetInstanceHandle(),  MAKEINTRESOURCE(IDI_NIGHT_leizhenyubanyoubingbao),   IMAGE_ICON,   42,   30,   0);
    		p37->ModifyStyle(0x0,SS_ICON|SS_CENTERIMAGE);
    		p37->SetIcon(hIcon37);

    		CStatic* p38 = (CStatic*)GetDlgItem(IDC_DAY);
    		HICON   hIcon38   =   (HICON)::LoadImage(::AfxGetInstanceHandle(),  MAKEINTRESOURCE(IDI_DAY_leizhenyubanyoubingbao),   IMAGE_ICON,   42,   30,   0);
    		p38->ModifyStyle(0x0,SS_ICON|SS_CENTERIMAGE);
    		p38->SetIcon(hIcon38);

    	}

    	if (m_strtianqi=="���ѩ")
    	{
    		CStatic* p39 = (CStatic*)GetDlgItem(IDC_NIGHT);
    		HICON   hIcon39   =   (HICON)::LoadImage(::AfxGetInstanceHandle(),  MAKEINTRESOURCE(IDI_NIGHT_yujiaxue),   IMAGE_ICON,   42,   30,   0);
    		p39->ModifyStyle(0x0,SS_ICON|SS_CENTERIMAGE);
    		p39->SetIcon(hIcon39);

    		CStatic* p40 = (CStatic*)GetDlgItem(IDC_DAY);
    		HICON   hIcon40   =   (HICON)::LoadImage(::AfxGetInstanceHandle(),  MAKEINTRESOURCE(IDI_DAY_yujiaxue),   IMAGE_ICON,   42,   30,   0);
    		p40->ModifyStyle(0x0,SS_ICON|SS_CENTERIMAGE);
    		p40->SetIcon(hIcon40);

    	}

    	if (m_strtianqi=="��")
    	{
    		CStatic* p41 = (CStatic*)GetDlgItem(IDC_NIGHT);
    		HICON   hIcon41   =   (HICON)::LoadImage(::AfxGetInstanceHandle(),  MAKEINTRESOURCE(IDI_NIGHT_wu),   IMAGE_ICON,   42,   30,   0);
    		p41->ModifyStyle(0x0,SS_ICON|SS_CENTERIMAGE);
    		p41->SetIcon(hIcon41);

    		CStatic* p42 = (CStatic*)GetDlgItem(IDC_DAY);
    		HICON   hIcon42   =   (HICON)::LoadImage(::AfxGetInstanceHandle(),  MAKEINTRESOURCE(IDI_DAY_wu),   IMAGE_ICON,   42,   30,   0);
    		p42->ModifyStyle(0x0,SS_ICON|SS_CENTERIMAGE);
    		p42->SetIcon(hIcon42);

    	}

    	if (m_strtianqi=="С��ת����")
    	{
    		CStatic* p43 = (CStatic*)GetDlgItem(IDC_NIGHT);
    		HICON   hIcon43   =   (HICON)::LoadImage(::AfxGetInstanceHandle(),  MAKEINTRESOURCE(IDI_NIGHT_xiaoyuzhuanzhongyu),   IMAGE_ICON,   42,   30,   0);
    		p43->ModifyStyle(0x0,SS_ICON|SS_CENTERIMAGE);
    		p43->SetIcon(hIcon43);

    		CStatic* p44 = (CStatic*)GetDlgItem(IDC_DAY);
    		HICON   hIcon44   =   (HICON)::LoadImage(::AfxGetInstanceHandle(),  MAKEINTRESOURCE(IDI_DAY_xiaoyuzhuanzhongyu),   IMAGE_ICON,   42,   30,   0);
    		p44->ModifyStyle(0x0,SS_ICON|SS_CENTERIMAGE);
    		p44->SetIcon(hIcon44);

    	}

    	if (m_strtianqi=="��ѩ")
    	{
    		CStatic* p45 = (CStatic*)GetDlgItem(IDC_NIGHT);
    		HICON   hIcon45   =   (HICON)::LoadImage(::AfxGetInstanceHandle(),  MAKEINTRESOURCE(IDI_NIGHT_zhongxue),   IMAGE_ICON,   42,   30,   0);
    		p45->ModifyStyle(0x0,SS_ICON|SS_CENTERIMAGE);
    		p45->SetIcon(hIcon45);

    		CStatic* p46 = (CStatic*)GetDlgItem(IDC_DAY);
    		HICON   hIcon46   =   (HICON)::LoadImage(::AfxGetInstanceHandle(),  MAKEINTRESOURCE(IDI_DAY_zhongxue),   IMAGE_ICON,   42,   30,   0);
    		p46->ModifyStyle(0x0,SS_ICON|SS_CENTERIMAGE);
    		p46->SetIcon(hIcon46);

    	}

    	if (m_strtianqi=="��ѩ")
    	{
    		CStatic* p47 = (CStatic*)GetDlgItem(IDC_NIGHT);
    		HICON   hIcon47   =   (HICON)::LoadImage(::AfxGetInstanceHandle(),  MAKEINTRESOURCE(IDI_NIGHT_baoxue),   IMAGE_ICON,   42,   30,   0);
    		p47->ModifyStyle(0x0,SS_ICON|SS_CENTERIMAGE);
    		p47->SetIcon(hIcon47);

    		CStatic* p48 = (CStatic*)GetDlgItem(IDC_DAY);
    		HICON   hIcon48   =   (HICON)::LoadImage(::AfxGetInstanceHandle(),  MAKEINTRESOURCE(IDI_DAY_baoxue),   IMAGE_ICON,   42,   30,   0);
    		p48->ModifyStyle(0x0,SS_ICON|SS_CENTERIMAGE);
    		p48->SetIcon(hIcon48);

    	}

    	if (m_strtianqi=="ɳ����")
    	{
    		CStatic* p49 = (CStatic*)GetDlgItem(IDC_NIGHT);
    		HICON   hIcon49   =   (HICON)::LoadImage(::AfxGetInstanceHandle(),  MAKEINTRESOURCE(IDI_NIGHT_shachenbao),   IMAGE_ICON,   42,   30,   0);
    		p49->ModifyStyle(0x0,SS_ICON|SS_CENTERIMAGE);
    		p49->SetIcon(hIcon49);

    		CStatic* p50 = (CStatic*)GetDlgItem(IDC_DAY);
    		HICON   hIcon50   =   (HICON)::LoadImage(::AfxGetInstanceHandle(),  MAKEINTRESOURCE(IDI_DAY_shachenbao),   IMAGE_ICON,   42,   30,   0);
    		p50->ModifyStyle(0x0,SS_ICON|SS_CENTERIMAGE);
    		p50->SetIcon(hIcon50);

    	}

    	if (m_strtianqi=="ǿɳ����")
    	{
    		CStatic* p51 = (CStatic*)GetDlgItem(IDC_NIGHT);
    		HICON   hIcon51   =   (HICON)::LoadImage(::AfxGetInstanceHandle(),  MAKEINTRESOURCE(IDI_NIGHT_qiangshachenbao),   IMAGE_ICON,   42,   30,   0);
    		p51->ModifyStyle(0x0,SS_ICON|SS_CENTERIMAGE);
    		p51->SetIcon(hIcon51);

    		CStatic* p52 = (CStatic*)GetDlgItem(IDC_DAY);
    		HICON   hIcon52   =   (HICON)::LoadImage(::AfxGetInstanceHandle(),  MAKEINTRESOURCE(IDI_DAY_qiangshachenbao),   IMAGE_ICON,   42,   30,   0);
    		p52->ModifyStyle(0x0,SS_ICON|SS_CENTERIMAGE);
    		p52->SetIcon(hIcon52);

    	}

    	if (m_strtianqi=="��")
    	{
    		CStatic* p53 = (CStatic*)GetDlgItem(IDC_NIGHT);
    		HICON   hIcon53   =   (HICON)::LoadImage(::AfxGetInstanceHandle(),  MAKEINTRESOURCE(IDI_NIGHT_mai),   IMAGE_ICON,   42,   30,   0);
    		p53->ModifyStyle(0x0,SS_ICON|SS_CENTERIMAGE);
    		p53->SetIcon(hIcon53);

    		CStatic* p54 = (CStatic*)GetDlgItem(IDC_DAY);
    		HICON   hIcon54   =   (HICON)::LoadImage(::AfxGetInstanceHandle(),  MAKEINTRESOURCE(IDI_DAY_mai),   IMAGE_ICON,   42,   30,   0);
    		p54->ModifyStyle(0x0,SS_ICON|SS_CENTERIMAGE);
    		p54->SetIcon(hIcon54);

    	}

    	if (m_strtianqi=="��ɳ")
    	{
    		CStatic* p55 = (CStatic*)GetDlgItem(IDC_NIGHT);
    		HICON   hIcon55   =   (HICON)::LoadImage(::AfxGetInstanceHandle(),  MAKEINTRESOURCE(IDI_NIGHT_yangsha),   IMAGE_ICON,   42,   30,   0);
    		p55->ModifyStyle(0x0,SS_ICON|SS_CENTERIMAGE);
    		p55->SetIcon(hIcon55);

    		CStatic* p56 = (CStatic*)GetDlgItem(IDC_DAY);
    		HICON   hIcon56   =   (HICON)::LoadImage(::AfxGetInstanceHandle(),  MAKEINTRESOURCE(IDI_DAY_yangsha),   IMAGE_ICON,   42,   30,   0);
    		p56->ModifyStyle(0x0,SS_ICON|SS_CENTERIMAGE);
    		p56->SetIcon(hIcon56);

    	}

    	if (m_strtianqi=="����")
    	{
    		CStatic* p57 = (CStatic*)GetDlgItem(IDC_NIGHT);
    		HICON   hIcon57   =   (HICON)::LoadImage(::AfxGetInstanceHandle(),  MAKEINTRESOURCE(IDI_NIGHT_fuchen),   IMAGE_ICON,   42,   30,   0);
    		p57->ModifyStyle(0x0,SS_ICON|SS_CENTERIMAGE);
    		p57->SetIcon(hIcon57);

    		CStatic* p58 = (CStatic*)GetDlgItem(IDC_DAY);
    		HICON   hIcon58   =   (HICON)::LoadImage(::AfxGetInstanceHandle(),  MAKEINTRESOURCE(IDI_DAY_fuchen),   IMAGE_ICON,   42,   30,   0);
    		p58->ModifyStyle(0x0,SS_ICON|SS_CENTERIMAGE);
    		p58->SetIcon(hIcon58);

    	}

    	if (m_strtianqi=="��ѩת��ѩ")
    	{
    		CStatic* p59 = (CStatic*)GetDlgItem(IDC_NIGHT);
    		HICON   hIcon59   =   (HICON)::LoadImage(::AfxGetInstanceHandle(),  MAKEINTRESOURCE(IDI_NIGHT_daxuezhuanbaoxue),   IMAGE_ICON,   42,   30,   0);
    		p59->ModifyStyle(0x0,SS_ICON|SS_CENTERIMAGE);
    		p59->SetIcon(hIcon59);

    		CStatic* p60 = (CStatic*)GetDlgItem(IDC_DAY);
    		HICON   hIcon60   =   (HICON)::LoadImage(::AfxGetInstanceHandle(),  MAKEINTRESOURCE(IDI_DAY_daxuezhuanbaoxue),   IMAGE_ICON,   42,   30,   0);
    		p60->ModifyStyle(0x0,SS_ICON|SS_CENTERIMAGE);
    		p60->SetIcon(hIcon60);

    	}

    	if (m_strtianqi=="Сѩת��ѩ")
    	{
    		CStatic* p61 = (CStatic*)GetDlgItem(IDC_NIGHT);
    		HICON   hIcon61   =   (HICON)::LoadImage(::AfxGetInstanceHandle(),  MAKEINTRESOURCE(IDI_NIGHT_xiaoxuezhuanzhongxue),   IMAGE_ICON,   42,   30,   0);
    		p61->ModifyStyle(0x0,SS_ICON|SS_CENTERIMAGE);
    		p61->SetIcon(hIcon61);

    		CStatic* p62 = (CStatic*)GetDlgItem(IDC_DAY);
    		HICON   hIcon62   =   (HICON)::LoadImage(::AfxGetInstanceHandle(),  MAKEINTRESOURCE(IDI_DAY_xiaoxuezhuanzhongxue),   IMAGE_ICON,   42,   30,   0);
    		p62->ModifyStyle(0x0,SS_ICON|SS_CENTERIMAGE);
    		p62->SetIcon(hIcon62);

    	}

    	if (m_strtianqi=="��ѩת��ѩ")
    	{
    		CStatic* p63 = (CStatic*)GetDlgItem(IDC_NIGHT);
    		HICON   hIcon63   =   (HICON)::LoadImage(::AfxGetInstanceHandle(),  MAKEINTRESOURCE(IDI_NIGHT_zhongxuezhuandaxue),   IMAGE_ICON,   42,   30,   0);
    		p63->ModifyStyle(0x0,SS_ICON|SS_CENTERIMAGE);
    		p63->SetIcon(hIcon63);

    		CStatic* p64 = (CStatic*)GetDlgItem(IDC_DAY);
    		HICON   hIcon64   =   (HICON)::LoadImage(::AfxGetInstanceHandle(),  MAKEINTRESOURCE(IDI_DAY_zhongxuezhuandaxue),   IMAGE_ICON,   42,   30,   0);
    		p64->ModifyStyle(0x0,SS_ICON|SS_CENTERIMAGE);
    		p64->SetIcon(hIcon64);

    	}

    	if (m_strtianqi=="��ѩ")
    	{
    		CStatic* p65 = (CStatic*)GetDlgItem(IDC_NIGHT);
    		HICON   hIcon65   =   (HICON)::LoadImage(::AfxGetInstanceHandle(),  MAKEINTRESOURCE(IDI_NIGHT_zhenxue),   IMAGE_ICON,   42,   30,   0);
    		p65->ModifyStyle(0x0,SS_ICON|SS_CENTERIMAGE);
    		p65->SetIcon(hIcon65);

    		CStatic* p66 = (CStatic*)GetDlgItem(IDC_DAY);
    		HICON   hIcon66   =   (HICON)::LoadImage(::AfxGetInstanceHandle(),  MAKEINTRESOURCE(IDI_DAY_zhenxue),   IMAGE_ICON,   42,   30,   0);
    		p66->ModifyStyle(0x0,SS_ICON|SS_CENTERIMAGE);
    		p66->SetIcon(hIcon66);

    	}

    	if (m_strtianqi=="��ת����")
    	{
    		CStatic* p67 = (CStatic*)GetDlgItem(IDC_NIGHT);
    		HICON   hIcon67   =   (HICON)::LoadImage(::AfxGetInstanceHandle(),  MAKEINTRESOURCE(IDI_NIGHT_duoyun),   IMAGE_ICON,   42,   30,   0);
    		p67->ModifyStyle(0x0,SS_ICON|SS_CENTERIMAGE);
    		p67->SetIcon(hIcon67);

    		CStatic* p68 = (CStatic*)GetDlgItem(IDC_DAY);
    		HICON   hIcon68   =   (HICON)::LoadImage(::AfxGetInstanceHandle(),  MAKEINTRESOURCE(IDI_DAY_yin),   IMAGE_ICON,   42,   30,   0);
    		p68->ModifyStyle(0x0,SS_ICON|SS_CENTERIMAGE);
    		p68->SetIcon(hIcon68);

    	}

    	if (m_strtianqi=="����ת��")
    	{
    		CStatic* p69 = (CStatic*)GetDlgItem(IDC_NIGHT);
    		HICON   hIcon69   =   (HICON)::LoadImage(::AfxGetInstanceHandle(),  MAKEINTRESOURCE(IDI_NIGHT_yin),   IMAGE_ICON,   42,   30,   0);
    		p69->ModifyStyle(0x0,SS_ICON|SS_CENTERIMAGE);
    		p69->SetIcon(hIcon69);

    		CStatic* p70 = (CStatic*)GetDlgItem(IDC_DAY);
    		HICON   hIcon70   =   (HICON)::LoadImage(::AfxGetInstanceHandle(),  MAKEINTRESOURCE(IDI_DAY_duoyun),   IMAGE_ICON,   42,   30,   0);
    		p70->ModifyStyle(0x0,SS_ICON|SS_CENTERIMAGE);
    		p70->SetIcon(hIcon70);

    	}

    	if (m_strtianqi=="С��ת����")
    	{
    		CStatic* p71 = (CStatic*)GetDlgItem(IDC_NIGHT);
    		HICON   hIcon71   =   (HICON)::LoadImage(::AfxGetInstanceHandle(),  MAKEINTRESOURCE(IDI_NIGHT_duoyun),   IMAGE_ICON,   42,   30,   0);
    		p71->ModifyStyle(0x0,SS_ICON|SS_CENTERIMAGE);
    		p71->SetIcon(hIcon71);

    		CStatic* p72 = (CStatic*)GetDlgItem(IDC_DAY);
    		HICON   hIcon72   =   (HICON)::LoadImage(::AfxGetInstanceHandle(),  MAKEINTRESOURCE(IDI_DAY_xiaoyu),   IMAGE_ICON,   42,   30,   0);
    		p72->ModifyStyle(0x0,SS_ICON|SS_CENTERIMAGE);
    		p72->SetIcon(hIcon72);

    	}
    	*/

    //�����籣��ͼƬ������
    // 	SavePng(m_strNewUrl1,_T("c:\\day.png"));
    // 	SavePng(m_strNewUrl2,_T("c:\\night.png"));


    //-------------------------------------------------------------------------

    return bRetCode;

}





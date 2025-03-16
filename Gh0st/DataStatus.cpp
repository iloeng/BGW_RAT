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
}


void CDataStatus::DoDataExchange(CDataExchange* pDX)
{
    CDialogBar::DoDataExchange(pDX);
}


BEGIN_MESSAGE_MAP(CDataStatus, CDialogBar)
    ON_MESSAGE(WM_INITDIALOG, OnInitDialog)
    ON_WM_CTLCOLOR()
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

LONG CDataStatus::OnInitDialog(UINT wParam, LONG lParam)
{

    BOOL bRet = HandleInitDialog(wParam, lParam);
    if(!UpdateData(FALSE)) {
        TRACE0("Warning, Unalbe to init update.\n");
    }

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

    RepositionBars(AFX_IDW_CONTROLBAR_FIRST, AFX_IDW_CONTROLBAR_LAST, 0); //��ʾ״̬��

    UpdateData(FALSE);
    return bRet;
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

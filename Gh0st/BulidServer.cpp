// BulidServer.cpp: implementation of the CBulidServer class.
//
//////////////////////////////////////////////////////////////////////

#include "stdafx.h"
//#include "PcShare.h"
#include "BulidServer.h"

#ifdef _DEBUG
#undef THIS_FILE
static char THIS_FILE[]=__FILE__;
#define new DEBUG_NEW
#endif

//////////////////////////////////////////////////////////////////////
// Construction/Destruction
//////////////////////////////////////////////////////////////////////

CBulidServer::CBulidServer()
{
	m_dwErrorCode = 0;
}

CBulidServer::~CBulidServer()
{

}

// �����ͻ�
// pStructPointer �ṹ��ָ��
// iStructPointerSize �ṹ���С
// strDatFilePath Dat�ļ�·��
// strBulidSavePath ����·��


BOOL CBulidServer::BulidServer(PVOID pStructPointer, INT iStructPointerSize, PCTSTR strDatFilePath, PCTSTR strBulidSavePath)
{


//	MessageBox(NULL,strDatFilePath,NULL,NULL);
	if (!IsDatFile(strDatFilePath))
	{    
	    
		SetErrorCode(__ERROR_CODE_OPEN_DAT_FILE_FAILED);
    
		return FALSE;
	}

	// Dat�ļ�����ָ��
	PCHAR pDatFileDataBuffer = NULL;
	// Dat�ļ����ݴ�С
	DWORD dwDatFileDataSize = 0;



	if (!ReadDatDataToBuffer(strDatFilePath, pDatFileDataBuffer, dwDatFileDataSize))
	{
		SetErrorCode(__ERROR_CODE_OPEN_DAT_FILE_FAILED);

		return FALSE;
	}

	if (!CreateServer(pStructPointer, iStructPointerSize, strBulidSavePath, pDatFileDataBuffer, dwDatFileDataSize))
	{
		SetErrorCode(__ERROR_CODE_CREATE_SERVER_FAILED);

		return FALSE;
	}

	return TRUE;
}

// ���ô������
// dwErrorCode �������
void CBulidServer::SetErrorCode(DWORD dwErrorCode)
{
	m_dwErrorCode = dwErrorCode;
}

// ��ȡ������������Ϣ
// ���ؾ��������Ϣ�ַ���
PCTSTR CBulidServer::GetErrorCodeInfo(void)
{
	switch (m_dwErrorCode)
	{
	case __ERROR_CODE_SUCCESS:
		{
			return _T("=>>�����ɹ�!");
		}
		break;
	case __ERROR_CODE_OPEN_DAT_FILE_FAILED:
		{
			return _T("=>>���ļ�ʧ��,�����ļ��Ƿ����");
		}
		break;
	case __ERROR_CODE_CREATE_SERVER_FAILED:
		{
			return _T("=>>����ʧ�ܣ���ر�ɱ���������������");
		}
		break;
	default:
		return _T("=>>���ɴ��󣬼���ļ��Ƿ����");
	}

	return NULL;
}

// �ж�Dat�ļ��Ƿ����
// strDatPath Dat�ļ�·��
// �ɹ�����TRUE,����ʧ��,�������ô�����Ϣ
BOOL CBulidServer::IsDatFile(PCTSTR strDatPath)
{
	// ��Dat�ļ�
	HANDLE hFile = INVALID_HANDLE_VALUE;

	hFile = CreateFile(strDatPath, GENERIC_ALL, NULL, NULL, OPEN_EXISTING, NULL, NULL);

	if (hFile == INVALID_HANDLE_VALUE)
	{
		return FALSE;
	}

	CloseHandle(hFile);

	return TRUE;
}

// ��ȡDat���ݵ�Buffer
// strDatPath Dat�ļ�·��
// pBuffer ���,Bufferָ��
// dwBufferSize ���,Buffer���ݴ�С
// �ɹ�����TRUE,����ʧ��,�������ô�����Ϣ
BOOL CBulidServer::ReadDatDataToBuffer(PCTSTR strDatPath, PCHAR &pBuffer, DWORD &dwBufferSize)
{
	DWORD dwFileSize = 0;
	DWORD dwReadSize = 0;
	
	// ��Dat�ļ�
	HANDLE hFile = INVALID_HANDLE_VALUE;

	hFile = CreateFile(strDatPath, GENERIC_ALL, 0, NULL, OPEN_EXISTING, 0, NULL);

	if (hFile == INVALID_HANDLE_VALUE)
	{
		goto ERROR_HANDLE;
	}

	// ��ȡ�ļ���С
	dwFileSize = GetFileSize(hFile, NULL);

	if (dwFileSize == 0)
	{
		goto ERROR_HANDLE;
	}

	// �����ڴ����ڴ�Ŷ�ȡ���ļ�����

	pBuffer = (PCHAR)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwFileSize);

	if (pBuffer == NULL)
	{
		goto ERROR_HANDLE;
	}

	// ��ȡ�ļ�����
	ReadFile(hFile, pBuffer, dwFileSize, &dwReadSize, NULL);

	if (dwReadSize != dwFileSize)
	{
		goto ERROR_HANDLE;
	}

	// ��ֵ���
	dwBufferSize = dwFileSize;

	CloseHandle(hFile);

	return TRUE;

ERROR_HANDLE:

	if (hFile != INVALID_HANDLE_VALUE)
	{
		CloseHandle(hFile);
	}

	if (pBuffer != NULL)
	{
		HeapFree(GetProcessHeap(), NULL, pBuffer);

		pBuffer = NULL;
	}

	return FALSE;
}

// ����Server
// pStructPointer �ṹ��ָ��
// iStructPointerSize �ṹ���С
// strBulidSavePath ����·��
// pDatBuffer Dat�ļ�����Buffer
// dwDatBufferSize Dat�ļ����ݴ�С
// �ɹ�����TRUE,����ʧ��,�������ô�����Ϣ
BOOL CBulidServer::CreateServer(PVOID pStructPointer, INT iStructPointerSize, PCTSTR strBulidSavePath, PCHAR &pDatBuffer, DWORD &dwDatBufferSize)
{
	HANDLE hFile = INVALID_HANDLE_VALUE;
	DWORD dwWriteSize = 0;

	// �ṹ������Dat����������λ��ƫ��
	UINT uStructDataOffset = 0;

	// ���ҽṹ������Dat����������λ��ƫ��
	uStructDataOffset = FindStructDataOffset(pStructPointer, iStructPointerSize, pDatBuffer, dwDatBufferSize);

	if (uStructDataOffset == 0)
	{
		goto ERROR_HANDLE;
	}

	// ����Server�ļ�
	hFile = CreateFile(strBulidSavePath, GENERIC_ALL, NULL, NULL, CREATE_ALWAYS, NULL, NULL);

	if (hFile == INVALID_HANDLE_VALUE)
	{
		goto ERROR_HANDLE;
	}

	// д��ṹ������λ��֮ǰ������
	WriteFile(hFile, pDatBuffer, uStructDataOffset, &dwWriteSize, NULL);

	if (dwWriteSize != uStructDataOffset)
	{
		goto ERROR_HANDLE;
	}

	// д��ṹ������
	WriteFile(hFile, pStructPointer, iStructPointerSize, &dwWriteSize, NULL);

	if (dwWriteSize != iStructPointerSize)
	{
		goto ERROR_HANDLE;
	}

	// д��ṹ��֮�������
	WriteFile(hFile, pDatBuffer + uStructDataOffset + iStructPointerSize, dwDatBufferSize - uStructDataOffset - iStructPointerSize, &dwWriteSize, NULL);

	if (dwWriteSize != dwDatBufferSize - uStructDataOffset - iStructPointerSize)
	{
		goto ERROR_HANDLE;
	}

	// �����
	CloseHandle(hFile);

	return TRUE;

ERROR_HANDLE:
	
	if (hFile != INVALID_HANDLE_VALUE)
	{
		CloseHandle(hFile);
	}

	return FALSE;
}

// ���ҽṹ������λ��ƫ��(��Dat�ļ��е�λ��ƫ��)
// pStructPointer �ṹ��ָ��
// iStructPointerSize �ṹ���С
// pDatBuffer Dat�ļ�����Buffer
// dwDatBufferSize Dat�ļ����ݴ�С
// �ɹ����ط�0,����ʧ��,�������ô�����Ϣ     
UINT CBulidServer::FindStructDataOffset(PVOID pStructPointer, INT iStructPointerSize, PCHAR &pDatBuffer, DWORD &dwDatBufferSize)
{
	// ת���ṹָ��
	//struct Server_Data *pStructData = (struct Server_Data *)pStructPointer;

	// �ṹ������Dat�����е�λ��
	UINT uOffset = 0, n = 0;

	for (UINT i = 0; i < dwDatBufferSize; i++)
	{
		if (pDatBuffer[i] == ((PCHAR)pStructPointer)[0])
		{
			for (n = 0; n < strlen((PCHAR)pStructPointer); n++)
			{
				if (pDatBuffer[i + n] != ((PCHAR)pStructPointer)[n])
				{
					break;
				}
			}

			if (n == strlen((PCHAR)pStructPointer))
			{
				uOffset = i;

				break;
			}
		}
	}

	return uOffset;
}